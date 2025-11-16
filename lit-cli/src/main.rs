use anyhow::Context;
use clap::{Parser, Subcommand};
use mime_guess::MimeGuess;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;
use uuid::Uuid;

use proto::operation_envelope::Payload;
use proto::relay_service_client::RelayServiceClient;
use proto::{
    FetchBlobRequest, HeartbeatRequest, ListRefsRequest, OpenSessionRequest, Operation,
    OperationEnvelope,
};

mod proto {
    tonic::include_proto!("lit.relay.v1");
}

#[derive(Parser, Debug)]
#[command(name = "lit", about = "lit CLI prototype")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Sync with a lit relay
    Sync(SyncArgs),
    /// Fetch a blob version
    BlobFetch(BlobFetchArgs),
}

#[derive(clap::Args, Debug)]
struct SyncArgs {
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    remote: String,
    #[arg(long)]
    token: Option<String>,
    #[arg(long)]
    node_id: Option<String>,
    #[arg(long = "send-file")]
    file: Option<PathBuf>,
    #[arg(long)]
    blob: bool,
}

#[derive(clap::Args, Debug)]
struct BlobFetchArgs {
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    remote: String,
    #[arg(long)]
    token: Option<String>,
    #[arg(long)]
    node_id: Option<String>,
    #[arg(long)]
    path: String,
    #[arg(long = "version")]
    version_id: String,
    #[arg(long)]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Sync(args) => run_sync(args).await?,
        Commands::BlobFetch(args) => run_blob_fetch(args).await?,
    }
    Ok(())
}

async fn run_sync(args: SyncArgs) -> anyhow::Result<()> {
    let mut client = relay_client(&args.remote).await?;
    let host = hostname();
    let node_id = args
        .node_id
        .clone()
        .unwrap_or_else(|| format!("{}-{}", host, Uuid::new_v4()));
    let mut open_req = Request::new(OpenSessionRequest {
        node_id: node_id.clone(),
        host: host.clone(),
        crdt_version: "1.0".into(),
        local_vector: None,
        auth_token: args.token.clone().unwrap_or_default(),
    });
    attach_auth(&mut open_req, args.token.as_deref())?;
    let session = client.open_session(open_req).await?.into_inner();
    println!("session: {}", session.session_id);

    let (tx, rx) = mpsc::channel::<OperationEnvelope>(8);
    let outbound = ReceiverStream::new(rx);
    let mut stream_req = Request::new(outbound);
    attach_auth(&mut stream_req, args.token.as_deref())?;
    let mut ack_stream = client.stream_ops(stream_req).await?.into_inner();

    if let Some(path) = args.file {
        let data = fs::read(&path)
            .await
            .with_context(|| format!("failed to read {:?}", path))?;
        let media_type = mime_string(&path);
        let op = Operation {
            op_id: 0,
            file_path: path.to_string_lossy().into_owned(),
            payload: data,
            media_type,
            is_blob: args.blob,
            timestamp: unix_timestamp(),
        };
        let envelope = OperationEnvelope {
            session_id: session.session_id.clone(),
            payload: Some(Payload::Operation(op)),
            checksum: vec![],
        };
        tx.send(envelope).await.unwrap();
    }
    drop(tx);

    while let Some(ack) = ack_stream.message().await? {
        println!("ack seq={}", ack.last_applied_op);
    }

    let mut hb_req = Request::new(HeartbeatRequest {
        session_id: session.session_id.clone(),
    });
    attach_auth(&mut hb_req, args.token.as_deref())?;
    let hb = client.heartbeat(hb_req).await?.into_inner();
    println!("heartbeat status: {}", hb.status);

    let mut list_req = Request::new(ListRefsRequest {
        session_id: session.session_id.clone(),
    });
    attach_auth(&mut list_req, args.token.as_deref())?;
    let refs = client.list_refs(list_req).await?.into_inner();
    println!(
        "labels={}, snapshots={}, blobs={}",
        refs.labels.len(),
        refs.snapshots.len(),
        refs.blobs.len()
    );
    Ok(())
}

async fn run_blob_fetch(args: BlobFetchArgs) -> anyhow::Result<()> {
    let mut client = relay_client(&args.remote).await?;
    let host = hostname();
    let node_id = args
        .node_id
        .clone()
        .unwrap_or_else(|| format!("{}-{}", host, Uuid::new_v4()));
    let mut open_req = Request::new(OpenSessionRequest {
        node_id,
        host,
        crdt_version: "1.0".into(),
        local_vector: None,
        auth_token: args.token.clone().unwrap_or_default(),
    });
    attach_auth(&mut open_req, args.token.as_deref())?;
    let session = client.open_session(open_req).await?.into_inner();

    let mut fetch_req = Request::new(FetchBlobRequest {
        session_id: session.session_id,
        path: args.path.clone(),
        version_id: args.version_id.clone(),
    });
    attach_auth(&mut fetch_req, args.token.as_deref())?;
    let resp = client.fetch_blob(fetch_req).await?.into_inner();
    fs::write(&args.output, &resp.data)
        .await
        .with_context(|| format!("failed to write {:?}", args.output))?;
    println!(
        "wrote {} bytes to {}",
        resp.data.len(),
        args.output.to_string_lossy()
    );
    Ok(())
}

fn attach_auth<T>(req: &mut Request<T>, token: Option<&str>) -> anyhow::Result<()> {
    if let Some(token) = token {
        let value = MetadataValue::try_from(format!("Bearer {token}"))?;
        req.metadata_mut().insert("authorization", value);
    }
    Ok(())
}

fn hostname() -> String {
    whoami::fallible::hostname().unwrap_or_else(|_| "unknown".into())
}

async fn relay_client(remote: &str) -> anyhow::Result<RelayServiceClient<Channel>> {
    let channel = Channel::from_shared(remote.to_string())?
        .connect()
        .await
        .context("failed to connect to relay")?;
    Ok(RelayServiceClient::new(channel))
}

fn mime_string(path: &PathBuf) -> String {
    MimeGuess::from_path(path)
        .first_or_octet_stream()
        .essence_str()
        .to_string()
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}
