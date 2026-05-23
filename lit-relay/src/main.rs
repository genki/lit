use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use chrono::Utc;
use clap::Parser;
use dashmap::DashMap;
use futures::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{error, info, warn};

mod proto {
    tonic::include_proto!("lit.relay.v1");
}

use proto::relay_service_server::{RelayService, RelayServiceServer};
use proto::{
    FetchSnapshotRequest, FetchSnapshotResponse, ListWorkspacesRequest, ListWorkspacesResponse,
    PublishSnapshotRequest, PublishSnapshotResponse, SnapshotEnvelope, SubscribeSnapshotsRequest,
    WorkspaceInfo,
};

#[derive(Parser, Debug)]
#[command(name = "lit-relay", about = "State-based snapshot relay for lit")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: String,
    #[arg(long, default_value = "./.lit-relay")]
    storage_root: PathBuf,
}

#[derive(Default, Serialize, Deserialize, Clone)]
struct WorkspaceMeta {
    latest_version: u64,
    updated_at: i64,
    hash: String,
    size_bytes: u64,
}

#[derive(Clone)]
struct SnapshotStore {
    root: Arc<PathBuf>,
}

impl SnapshotStore {
    fn new(root: PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(root.join("workspaces"))?;
        Ok(Self {
            root: Arc::new(root),
        })
    }

    fn workspace_dir(&self, slug: &str) -> PathBuf {
        self.root.join("workspaces").join(slug)
    }

    fn metadata_path(dir: &Path) -> PathBuf {
        dir.join("metadata.json")
    }

    fn snapshot_path(dir: &Path, version: u64) -> PathBuf {
        dir.join(format!("snapshot-{version:020}.json"))
    }

    fn load_meta(&self, dir: &Path) -> anyhow::Result<WorkspaceMeta> {
        let path = Self::metadata_path(dir);
        if !path.exists() {
            return Ok(WorkspaceMeta::default());
        }
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn save_meta(&self, dir: &Path, meta: &WorkspaceMeta) -> anyhow::Result<()> {
        let path = Self::metadata_path(dir);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(meta)?)?;
        Ok(())
    }

    fn ensure_slug(slug: &str) -> Result<(), Status> {
        if slug.is_empty() {
            return Err(Status::invalid_argument("workspace slug is required"));
        }
        if slug.len() > 128 {
            return Err(Status::invalid_argument("workspace slug too long"));
        }
        if !slug
            .chars()
            .all(|ch| matches!(ch, 'a'..='z' | '0'..='9' | '-' | '_'))
        {
            return Err(Status::invalid_argument(
                "workspace slug must be [-a-z0-9_-]",
            ));
        }
        Ok(())
    }

    fn publish_snapshot(
        &self,
        req: PublishSnapshotRequest,
    ) -> Result<PublishSnapshotResponse, Status> {
        Self::ensure_slug(&req.workspace)?;
        if req.snapshot_json.is_empty() {
            return Err(Status::invalid_argument("snapshot_json must not be empty"));
        }
        let dir = self.workspace_dir(&req.workspace);
        fs::create_dir_all(&dir)
            .map_err(|e| Status::internal(format!("failed to create workspace dir: {e}")))?;
        let mut meta = self
            .load_meta(&dir)
            .map_err(|e| Status::internal(format!("failed to read metadata: {e}")))?;
        let new_version = meta.latest_version.saturating_add(1);
        let snapshot_path = Self::snapshot_path(&dir, new_version);
        fs::write(&snapshot_path, &req.snapshot_json)
            .map_err(|e| Status::internal(format!("failed to store snapshot: {e}")))?;
        meta.latest_version = new_version;
        meta.updated_at = Utc::now().timestamp();
        meta.hash = req.hash;
        meta.size_bytes = req.size_bytes;
        self.save_meta(&dir, &meta)
            .map_err(|e| Status::internal(format!("failed to write metadata: {e}")))?;
        Ok(PublishSnapshotResponse {
            workspace: req.workspace,
            stored_version: new_version,
        })
    }

    fn fetch_snapshot(&self, workspace: &str) -> Result<FetchSnapshotResponse, Status> {
        Self::ensure_slug(workspace)?;
        let dir = self.workspace_dir(workspace);
        let meta = self
            .load_meta(&dir)
            .map_err(|e| Status::internal(format!("failed to read metadata: {e}")))?;
        if meta.latest_version == 0 {
            return Err(Status::not_found("workspace has no snapshots"));
        }
        let path = Self::snapshot_path(&dir, meta.latest_version);
        let data = fs::read(&path)
            .map_err(|e| Status::internal(format!("failed to read snapshot: {e}")))?;
        Ok(FetchSnapshotResponse {
            workspace: workspace.to_string(),
            snapshot_json: data,
            size_bytes: meta.size_bytes,
            hash: meta.hash,
            stored_version: meta.latest_version,
        })
    }

    fn list_workspaces(&self) -> anyhow::Result<Vec<WorkspaceInfo>> {
        let mut entries = Vec::new();
        let dir = self.root.join("workspaces");
        if !dir.exists() {
            return Ok(entries);
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if !entry.path().is_dir() {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                if Self::ensure_slug(name).is_err() {
                    continue;
                }
                let meta = self.load_meta(&entry.path()).unwrap_or_default();
                entries.push(WorkspaceInfo {
                    workspace: name.to_string(),
                    latest_version: meta.latest_version,
                    updated_at: meta.updated_at as u64,
                });
            }
        }
        Ok(entries)
    }
}

#[derive(Clone)]
struct SnapshotBroadcaster {
    channels: Arc<DashMap<String, broadcast::Sender<Arc<SnapshotEnvelope>>>>,
}

impl SnapshotBroadcaster {
    fn new() -> Self {
        Self {
            channels: Arc::new(DashMap::new()),
        }
    }

    fn subscribe(&self, workspace: &str) -> broadcast::Receiver<Arc<SnapshotEnvelope>> {
        self.sender(workspace).subscribe()
    }

    fn notify(&self, envelope: SnapshotEnvelope) {
        let workspace = envelope.workspace.clone();
        let sender = self.sender(&workspace);
        if sender.send(Arc::new(envelope)).is_err() {
            // No active subscribers; drop silently.
        }
    }

    fn sender(&self, workspace: &str) -> broadcast::Sender<Arc<SnapshotEnvelope>> {
        if let Some(sender) = self.channels.get(workspace) {
            return sender.value().clone();
        }
        let (sender, _) = broadcast::channel(32);
        self.channels.insert(workspace.to_string(), sender.clone());
        sender
    }
}

impl From<FetchSnapshotResponse> for SnapshotEnvelope {
    fn from(resp: FetchSnapshotResponse) -> Self {
        SnapshotEnvelope {
            workspace: resp.workspace,
            version: resp.stored_version,
            snapshot_json: resp.snapshot_json,
            size_bytes: resp.size_bytes,
            hash: resp.hash,
            published_at: Utc::now().timestamp() as u64,
        }
    }
}

fn broadcast_latest(
    store: &Arc<SnapshotStore>,
    broadcaster: &SnapshotBroadcaster,
    workspace: &str,
) {
    match store.fetch_snapshot(workspace) {
        Ok(resp) => broadcaster.notify(resp.into()),
        Err(err) => warn!(workspace = %workspace, "failed to fetch snapshot for broadcast: {err}"),
    }
}

#[derive(Clone)]
struct RelayServiceImpl {
    store: Arc<SnapshotStore>,
    broadcaster: SnapshotBroadcaster,
}

#[tonic::async_trait]
impl RelayService for RelayServiceImpl {
    type PublishSnapshotStreamStream =
        Pin<Box<dyn Stream<Item = Result<PublishSnapshotResponse, Status>> + Send + 'static>>;
    type SubscribeSnapshotsStream =
        Pin<Box<dyn Stream<Item = Result<SnapshotEnvelope, Status>> + Send + 'static>>;

    async fn publish_snapshot(
        &self,
        request: Request<PublishSnapshotRequest>,
    ) -> Result<Response<PublishSnapshotResponse>, Status> {
        let req = request.into_inner();
        let resp = self.store.publish_snapshot(req)?;
        let workspace = resp.workspace.clone();
        broadcast_latest(&self.store, &self.broadcaster, &workspace);
        Ok(Response::new(resp))
    }

    async fn fetch_snapshot(
        &self,
        request: Request<FetchSnapshotRequest>,
    ) -> Result<Response<FetchSnapshotResponse>, Status> {
        let req = request.into_inner();
        let resp = self.store.fetch_snapshot(&req.workspace)?;
        Ok(Response::new(resp))
    }

    async fn list_workspaces(
        &self,
        _request: Request<ListWorkspacesRequest>,
    ) -> Result<Response<ListWorkspacesResponse>, Status> {
        let workspaces = self
            .store
            .list_workspaces()
            .map_err(|e| Status::internal(format!("failed to list workspaces: {e}")))?;
        Ok(Response::new(ListWorkspacesResponse { workspaces }))
    }

    async fn publish_snapshot_stream(
        &self,
        request: Request<tonic::Streaming<PublishSnapshotRequest>>,
    ) -> Result<Response<Self::PublishSnapshotStreamStream>, Status> {
        let mut inbound = request.into_inner();
        let store = self.store.clone();
        let broadcaster = self.broadcaster.clone();
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            loop {
                let req = match inbound.message().await {
                    Ok(Some(msg)) => msg,
                    Ok(None) => break,
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
                        break;
                    }
                };
                let workspace = req.workspace.clone();
                match store.publish_snapshot(req) {
                    Ok(resp) => {
                        if tx.send(Ok(resp.clone())).await.is_err() {
                            break;
                        }
                        broadcast_latest(&store, &broadcaster, &workspace);
                    }
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
                        break;
                    }
                }
            }
        });
        Ok(Response::new(
            Box::pin(ReceiverStream::new(rx)) as Self::PublishSnapshotStreamStream
        ))
    }

    async fn subscribe_snapshots(
        &self,
        request: Request<SubscribeSnapshotsRequest>,
    ) -> Result<Response<Self::SubscribeSnapshotsStream>, Status> {
        let req = request.into_inner();
        SnapshotStore::ensure_slug(&req.workspace)?;
        let workspace = req.workspace.clone();
        let store = self.store.clone();
        let broadcaster = self.broadcaster.clone();
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            let mut last_version = req.from_version;
            if let Ok(resp) = store.fetch_snapshot(&workspace) {
                if resp.stored_version > last_version {
                    let env: SnapshotEnvelope = resp.into();
                    last_version = env.version;
                    if tx.send(Ok(env)).await.is_err() {
                        return;
                    }
                }
            }
            let mut subscriber = broadcaster.subscribe(&workspace);
            loop {
                match subscriber.recv().await {
                    Ok(env_arc) => {
                        let env = (*env_arc).clone();
                        if env.version <= last_version {
                            continue;
                        }
                        last_version = env.version;
                        if tx.send(Ok(env)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Ok(Response::new(
            Box::pin(ReceiverStream::new(rx)) as Self::SubscribeSnapshotsStream
        ))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let args = Args::parse();
    let store = Arc::new(SnapshotStore::new(args.storage_root.clone())?);
    let service = RelayServiceImpl {
        store: store.clone(),
        broadcaster: SnapshotBroadcaster::new(),
    };
    let addr: SocketAddr = args
        .listen
        .parse()
        .context("failed to parse listen address")?;
    info!(%addr, "starting lit snapshot relay");
    if let Err(err) = Server::builder()
        .add_service(RelayServiceServer::new(service))
        .serve(addr)
        .await
    {
        error!("relay server stopped: {err}");
        return Err(err.into());
    }
    Ok(())
}
