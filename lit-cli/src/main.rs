use anyhow::Context;
use clap::{Parser, Subcommand};
use futures::stream::{self, StreamExt};
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;
use uuid::Uuid;

use proto::relay_service_client::RelayServiceClient;
use proto::{HeartbeatRequest, ListRefsRequest, OpenSessionRequest, OperationEnvelope};

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
}

#[derive(clap::Args, Debug)]
struct SyncArgs {
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    remote: String,
    #[arg(long)]
    token: Option<String>,
    #[arg(long)]
    node_id: Option<String>,
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
    }
    Ok(())
}

async fn run_sync(args: SyncArgs) -> anyhow::Result<()> {
    let channel = Channel::from_shared(args.remote.clone())?
        .connect()
        .await
        .context("failed to connect to relay")?;
    let mut client = RelayServiceClient::new(channel);
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
    let response = client.open_session(open_req).await?.into_inner();
    println!("session: {}", response.session_id);

    let outbound = stream::empty::<OperationEnvelope>();
    let mut stream_req = Request::new(outbound);
    attach_auth(&mut stream_req, args.token.as_deref())?;
    let mut ack_stream = client.stream_ops(stream_req).await?.into_inner();
    while let Some(ack) = ack_stream.next().await.transpose()? {
        println!("ack seq={}", ack.last_applied_op);
    }

    let mut hb_req = Request::new(HeartbeatRequest {
        session_id: response.session_id.clone(),
    });
    attach_auth(&mut hb_req, args.token.as_deref())?;
    let hb = client.heartbeat(hb_req).await?.into_inner();
    println!("heartbeat status: {}", hb.status);

    let mut list_req = Request::new(ListRefsRequest {
        session_id: response.session_id.clone(),
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
