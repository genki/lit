use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context;
use async_stream::try_stream;
use clap::Parser;
use futures::Stream;
use futures::StreamExt;
use lit_storage::{FsBackend, StorageBackend, StorageConfig, StorageError};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use prost::Message;
use tokio::sync::RwLock;
use tonic::{service::Interceptor, transport::Server, Request, Response, Status};
use tracing::info;
use uuid::Uuid;

const PATH_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.');

use proto::relay_service_server::{RelayService, RelayServiceServer};
use proto::{
    operation_envelope::Payload, Ack, BlobRef, FetchBlobRequest, FetchBlobResponse,
    FetchSnapshotRequest, HeartbeatRequest, HeartbeatResponse, Label, LabelRef, ListRefsRequest,
    ListRefsResponse, OpenSessionRequest, OpenSessionResponse, OperationEnvelope, SnapshotChunk,
    SnapshotMeta,
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
    #[arg(long)]
    auth_token: Option<String>,
}

#[derive(Default)]
struct SessionState {
    node_id: String,
    last_op: u64,
}

#[derive(Clone)]
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

    async fn persist_payload(
        &self,
        session_id: &str,
        seq: u64,
        payload: &Payload,
    ) -> Result<(), Status> {
        match payload {
            Payload::Operation(op) => {
                let mut buf = Vec::new();
                op.encode(&mut buf)
                    .map_err(|e| Status::internal(format!("encode failure: {e}")))?;
                let key = format!("logs/{session_id}/{seq:020}.bin");
                self.storage
                    .put_object(&key, &buf)
                    .await
                    .map_err(|e| Status::internal(format!("store failure: {e}")))?;
                if op.is_blob {
                    let version_id = format!("{seq:020}");
                    self.store_blob(&op.file_path, &version_id, &op.payload)
                        .await?;
                }
            }
            Payload::Snapshot(snapshot) => {
                let mut buf = Vec::new();
                snapshot
                    .encode(&mut buf)
                    .map_err(|e| Status::internal(format!("encode failure: {e}")))?;
                let key = format!("snaps/meta/{}.bin", snapshot.snapshot_id);
                self.storage
                    .put_object(&key, &buf)
                    .await
                    .map_err(|e| Status::internal(format!("store failure: {e}")))?;
                let data_key = format!("snaps/data/{}.bin", snapshot.snapshot_id);
                if let Err(StorageError::NotFound(_)) = self.storage.get_object(&data_key).await {
                    self.storage
                        .put_object(&data_key, &[])
                        .await
                        .map_err(|e| Status::internal(format!("store failure: {e}")))?;
                }
            }
            Payload::Label(label) => {
                let mut buf = Vec::new();
                label
                    .encode(&mut buf)
                    .map_err(|e| Status::internal(format!("encode failure: {e}")))?;
                let key = format!("labels/{}.bin", label.label_id);
                self.storage
                    .put_object(&key, &buf)
                    .await
                    .map_err(|e| Status::internal(format!("store failure: {e}")))?;
            }
        }
        Ok(())
    }

    async fn store_blob(&self, path: &str, version_id: &str, data: &[u8]) -> Result<(), Status> {
        let key = format!("blobs/{}/{}", encode_blob_path(path), version_id);
        self.storage
            .put_object(&key, data)
            .await
            .map_err(|e| Status::internal(format!("store failure: {e}")))
    }
}

type ResponseStream = std::pin::Pin<Box<dyn Stream<Item = Result<Ack, Status>> + Send + 'static>>;
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
        let relay = self.clone();
        let sessions = relay.sessions.clone();
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
                let payload = envelope
                    .payload
                    .as_ref()
                    .ok_or_else(|| Status::invalid_argument("payload missing"))?;
                relay.persist_payload(&session_id, seq, payload).await?;
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
        let key = format!("snaps/data/{snapshot_id}.bin");
        match self.storage.get_object(&key).await {
            Ok(bytes) => {
                let chunk_size = 1024 * 1024;
                let total = std::cmp::max(1, (bytes.len() + chunk_size - 1) / chunk_size);
                let snapshot_id_clone = snapshot_id.clone();
                let chunks = bytes
                    .chunks(chunk_size)
                    .enumerate()
                    .map(move |(index, data)| SnapshotChunk {
                        snapshot_id: snapshot_id_clone.clone(),
                        data: data.to_vec(),
                        index: index as u32,
                        total: total as u32,
                    })
                    .collect::<Vec<_>>();
                let stream = tokio_stream::iter(chunks.into_iter().map(Ok));
                Ok(Response::new(Box::pin(stream) as ResponseStreamSnapshots))
            }
            Err(StorageError::NotFound(_)) => Err(Status::not_found("snapshot not found")),
            Err(err) => Err(Status::internal(format!("{err}"))),
        }
    }

    async fn fetch_blob(
        &self,
        request: Request<FetchBlobRequest>,
    ) -> Result<Response<FetchBlobResponse>, Status> {
        let req = request.into_inner();
        if req.path.is_empty() || req.version_id.is_empty() {
            return Err(Status::invalid_argument("path and version_id are required"));
        }
        let key = format!("blobs/{}/{}", encode_blob_path(&req.path), req.version_id);
        match self.storage.get_object(&key).await {
            Ok(data) => Ok(Response::new(FetchBlobResponse { data })),
            Err(StorageError::NotFound(_)) => Err(Status::not_found("blob not found")),
            Err(err) => Err(Status::internal(format!("{err}"))),
        }
    }

    async fn list_refs(
        &self,
        _request: Request<ListRefsRequest>,
    ) -> Result<Response<ListRefsResponse>, Status> {
        let mut label_refs = Vec::new();
        for key in self
            .storage
            .list_objects("labels")
            .await
            .map_err(|e| Status::internal(format!("{e}")))?
        {
            let bytes = self
                .storage
                .get_object(&key)
                .await
                .map_err(|e| Status::internal(format!("{e}")))?;
            let label = Label::decode(&*bytes)
                .map_err(|e| Status::internal(format!("decode failure: {e}")))?;
            label_refs.push(LabelRef {
                label_id: label.label_id,
                name: label.name,
                to_op: label.to_op,
            });
        }

        let mut snapshot_ids = Vec::new();
        for key in self
            .storage
            .list_objects("snaps/meta")
            .await
            .map_err(|e| Status::internal(format!("{e}")))?
        {
            let bytes = self
                .storage
                .get_object(&key)
                .await
                .map_err(|e| Status::internal(format!("{e}")))?;
            let meta = SnapshotMeta::decode(&*bytes)
                .map_err(|e| Status::internal(format!("decode failure: {e}")))?;
            snapshot_ids.push(meta.snapshot_id);
        }

        let mut blob_refs = Vec::new();
        for key in self
            .storage
            .list_objects("blobs")
            .await
            .map_err(|e| Status::internal(format!("{e}")))?
        {
            let parts: Vec<&str> = key.split('/').collect();
            if parts.len() != 3 {
                continue;
            }
            let encoded_path = parts[1];
            if let Some(path) = decode_blob_path(encoded_path) {
                let version_id = parts[2].to_string();
                blob_refs.push(BlobRef { path, version_id });
            }
        }
        let response = ListRefsResponse {
            labels: label_refs,
            snapshots: snapshot_ids,
            blobs: blob_refs,
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
    let addr: SocketAddr = args
        .listen
        .parse()
        .context("failed to parse listen address")?;
    info!(%addr, "starting lit-relay server");
    let interceptor = AuthInterceptor {
        token: args.auth_token.clone(),
    };
    let service = RelayServiceServer::with_interceptor(LitRelay::new(backend), interceptor);
    Server::builder()
        .add_service(service)
        .serve(addr)
        .await
        .context("server failure")?;
    Ok(())
}

fn verify_bearer<T>(req: &Request<T>, token: &str) -> Result<(), Status> {
    let expected = format!("Bearer {token}");
    match req.metadata().get("authorization") {
        Some(value) if value.to_str().map(|v| v == expected).unwrap_or(false) => Ok(()),
        _ => Err(Status::unauthenticated("invalid or missing token")),
    }
}

#[derive(Clone)]
struct AuthInterceptor {
    token: Option<String>,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        if let Some(token) = &self.token {
            verify_bearer(&req, token)?;
        }
        Ok(req)
    }
}

fn encode_blob_path(path: &str) -> String {
    utf8_percent_encode(path, PATH_ENCODE_SET).to_string()
}

fn decode_blob_path(encoded: &str) -> Option<String> {
    percent_decode_str(encoded)
        .decode_utf8()
        .ok()
        .map(|cow| cow.into_owned())
}
