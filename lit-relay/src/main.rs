use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context;
use async_stream::try_stream;
use clap::Parser;
use futures::Stream;
use futures::StreamExt;
use lit_storage::{FsBackend, StorageBackend, StorageConfig, StorageError};
use prost::Message;
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use proto::relay_service_server::{RelayService, RelayServiceServer};
use proto::{
    Ack, FetchSnapshotRequest, HeartbeatRequest, HeartbeatResponse, ListRefsRequest,
    ListRefsResponse, OperationEnvelope, OpenSessionRequest, OpenSessionResponse, SnapshotChunk,
};

mod proto {
    tonic::include_proto!("lit.relay.v1");
}

#[derive(Parser, Debug)]
#[command(name = "lit-relay", about = "Relay server for lit gRPC sync")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: String,
    #[arg(long, default_value = "./.lit-relay")]
    storage_root: PathBuf,
    #[arg(long, default_value = "fs", value_parser = ["fs", "mem"])]
    backend: String,
}

#[derive(Default)]
struct SessionState {
    node_id: String,
    last_op: u64,
}

struct LitRelay {
    storage: Arc<dyn StorageBackend>,
    sessions: Arc<RwLock<HashMap<String, SessionState>>>,
}

impl LitRelay {
    fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self {
            storage,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

type ResponseStream =
    std::pin::Pin<Box<dyn Stream<Item = Result<Ack, Status>> + Send + 'static>>;
type ResponseStreamSnapshots =
    std::pin::Pin<Box<dyn Stream<Item = Result<SnapshotChunk, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl RelayService for LitRelay {
    type StreamOpsStream = ResponseStream;
    type FetchSnapshotStream = ResponseStreamSnapshots;

    async fn open_session(
        &self,
        request: Request<OpenSessionRequest>,
    ) -> Result<Response<OpenSessionResponse>, Status> {
        let req = request.into_inner();
        let session_id = Uuid::new_v4().to_string();
        let vector = req.local_vector.clone().unwrap_or_default();
        let mut sessions = self.sessions.write().await;
        sessions.insert(
            session_id.clone(),
            SessionState {
                node_id: req.node_id.clone(),
                last_op: 0,
            },
        );
        let response = OpenSessionResponse {
            session_id,
            relay_vector: Some(vector),
            missing_log_ranges: vec![],
        };
        Ok(Response::new(response))
    }

    async fn stream_ops(
        &self,
        request: Request<tonic::Streaming<OperationEnvelope>>,
    ) -> Result<Response<Self::StreamOpsStream>, Status> {
        let mut stream = request.into_inner();
        let storage = self.storage.clone();
        let sessions = self.sessions.clone();
        let output = try_stream! {
            while let Some(item) = stream.next().await {
                let envelope = item?;
                let session_id = if envelope.session_id.is_empty() {
                    Err(Status::invalid_argument("session_id is required"))?
                } else {
                    envelope.session_id.clone()
                };
                let seq = {
                    let mut guard = sessions.write().await;
                    let state = guard
                        .get_mut(&session_id)
                        .ok_or_else(|| Status::not_found("unknown session"))?;
                    state.last_op += 1;
                    state.last_op
                };
                let key = format!("logs/{session_id}/{seq:020}.bin");
                let mut buf = Vec::new();
                envelope
                    .encode(&mut buf)
                    .map_err(|e| Status::internal(format!("encode failure: {e}")))?;
                storage
                    .put_object(&key, &buf)
                    .await
                    .map_err(|e| Status::internal(format!("store failure: {e}")))?;
                yield Ack {
                    session_id: session_id.clone(),
                    last_applied_op: seq,
                    error: String::new(),
                };
            }
        };
        Ok(Response::new(Box::pin(output) as ResponseStream))
    }

    async fn fetch_snapshot(
        &self,
        request: Request<FetchSnapshotRequest>,
    ) -> Result<Response<Self::FetchSnapshotStream>, Status> {
        let req = request.into_inner();
        let snapshot_id = req.snapshot_id;
        if snapshot_id.is_empty() {
            return Err(Status::invalid_argument("snapshot_id is required"));
        }
        let key = format!("snaps/{snapshot_id}.bin");
        match self.storage.get_object(&key).await {
            Ok(bytes) => {
                let chunk = SnapshotChunk {
                    snapshot_id,
                    data: bytes,
                    index: 0,
                    total: 1,
                };
                let stream = tokio_stream::iter(vec![Ok(chunk)]);
                Ok(Response::new(Box::pin(stream) as ResponseStreamSnapshots))
            }
            Err(StorageError::NotFound(_)) => Err(Status::not_found("snapshot not found")),
            Err(err) => Err(Status::internal(format!("{err}"))),
        }
    }

    async fn list_refs(
        &self,
        _request: Request<ListRefsRequest>,
    ) -> Result<Response<ListRefsResponse>, Status> {
        let response = ListRefsResponse {
            labels: vec![],
            snapshots: vec![],
            blobs: vec![],
        };
        Ok(Response::new(response))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let session_id = request.into_inner().session_id;
        let sessions = self.sessions.read().await;
        let node_id = sessions
            .get(&session_id)
            .map(|state| state.node_id.clone())
            .ok_or_else(|| Status::not_found("unknown session"))?;
        Ok(Response::new(HeartbeatResponse {
            session_id,
            status: format!("ok:{node_id}"),
        }))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();
    let args = Args::parse();
    let backend: Arc<dyn StorageBackend> = match args.backend.as_str() {
        "mem" => Arc::new(lit_storage::MemBackend::default()),
        _ => {
            let config = StorageConfig::new(&args.storage_root);
            Arc::new(FsBackend::new(config))
        }
    };
    let relay = LitRelay::new(backend);
    let addr: SocketAddr = args
        .listen
        .parse()
        .context("failed to parse listen address")?;
    info!(%addr, "starting lit-relay server");
    Server::builder()
        .add_service(RelayServiceServer::new(relay))
        .serve(addr)
        .await
        .context("server failure")?
        ;
    Ok(())
}
