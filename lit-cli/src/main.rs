use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use dirs::home_dir;
use hex::ToHex;
use libc;
use mime_guess::MimeGuess;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::mpsc;
use tokio::time::sleep;
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
    /// Turn on lit (mount a workspace via FUSE overlay)
    On(OnArgs),
    /// Turn off lit (unmount a workspace)
    Off(OffArgs),
    /// Show CLI version information
    Version,
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

#[derive(clap::Args, Debug)]
struct OnArgs {
    /// Target directory to initialize (defaults to current directory)
    path: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct OffArgs {
    /// Targetディレクトリ(省略時はカレント)
    path: Option<PathBuf>,
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
        Commands::On(args) => run_on(args).await?,
        Commands::Off(args) => run_off(args).await?,
        Commands::Version => run_version(),
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

fn run_version() {
    println!("lit {}", env!("CARGO_PKG_VERSION"));
}

async fn run_on(args: OnArgs) -> anyhow::Result<()> {
    let target = match args.path {
        Some(p) => p,
        None => std::env::current_dir()?,
    };
    let canonical_target = fs::canonicalize(&target).await.unwrap_or(target.clone());
    ensure_dir(&canonical_target).await?;
    ensure_fuse_overlayfs()?;

    let lit_home = lit_home_dir()?;
    let workspaces_root = lit_home.join("workspaces");
    fs::create_dir_all(&workspaces_root).await?;

    let workspace_id = workspace_id(&canonical_target).await?;
    let workspace_root = workspaces_root.join(&workspace_id);
    let lower = workspace_root.join("lower");
    let upper = workspace_root.join("upper");
    let work = workspace_root.join("work");
    fs::create_dir_all(&lower).await?;
    fs::create_dir_all(&upper).await?;
    fs::create_dir_all(&work).await?;

    move_existing_contents(&canonical_target, &lower)?;
    write_workspace_marker(&lower, &workspace_id)?;
    write_workspace_config(
        &workspace_root,
        &canonical_target,
        &workspace_id,
        &lower,
        &upper,
        &work,
    )?;

    mount_overlay(&canonical_target, &lower, &upper, &work)?;
    // Give the daemon a moment to mount before exiting
    sleep(Duration::from_millis(500)).await;
    println!(
        "lit: mounted workspace {} at {}",
        workspace_id,
        canonical_target.to_string_lossy()
    );
    println!(
        "Turn off with: lit off {}",
        canonical_target.to_string_lossy()
    );
    Ok(())
}

async fn run_off(args: OffArgs) -> anyhow::Result<()> {
    let target = match args.path {
        Some(p) => p,
        None => std::env::current_dir()?,
    };
    let canonical = fs::canonicalize(&target).await.unwrap_or(target.clone());
    let status = Command::new("fusermount3")
        .arg("-u")
        .arg(&canonical)
        .status()
        .map_err(|e| anyhow!("failed to run fusermount3: {e}"))?;
    if !status.success() {
        return Err(anyhow!(
            "fusermount3 exited with status {} for {}",
            status,
            canonical.display()
        ));
    }
    println!("lit: unmounted {}", canonical.display());
    Ok(())
}

async fn ensure_dir(path: &Path) -> anyhow::Result<()> {
    if !tokio::fs::metadata(path).await?.is_dir() {
        return Err(anyhow!("{} is not a directory", path.display()));
    }
    Ok(())
}

fn ensure_fuse_overlayfs() -> anyhow::Result<()> {
    which::which("fuse-overlayfs")
        .map(|_| ())
        .map_err(|_| anyhow!("fuse-overlayfs not found; install fuse-overlayfs package"))
}

async fn workspace_id(path: &Path) -> anyhow::Result<String> {
    let canonical = tokio::fs::canonicalize(path)
        .await
        .unwrap_or(path.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    Ok(hasher.finalize().encode_hex::<String>())
}

fn lit_home_dir() -> anyhow::Result<PathBuf> {
    let home = home_dir().ok_or_else(|| anyhow!("cannot determine home directory"))?;
    let lit_home = home.join(".lit");
    std::fs::create_dir_all(&lit_home)?;
    Ok(lit_home)
}

fn move_existing_contents(source: &Path, lower: &Path) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let dest = lower.join(&name);
        std::fs::create_dir_all(dest.parent().unwrap_or(lower))?;
        move_entry(&entry.path(), &dest)?;
    }
    Ok(())
}

fn move_entry(source: &Path, dest: &Path) -> anyhow::Result<()> {
    match std::fs::rename(source, dest) {
        Ok(()) => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {
            copy_recursive(source, dest)?;
            if source.is_dir() {
                std::fs::remove_dir_all(source)?;
            } else {
                std::fs::remove_file(source)?;
            }
            Ok(())
        }
        Err(err) => Err(anyhow!(
            "failed to move {} to {}: {}",
            source.display(),
            dest.display(),
            err
        )),
    }
}

fn copy_recursive(source: &Path, dest: &Path) -> anyhow::Result<()> {
    if source.is_dir() {
        std::fs::create_dir_all(dest)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let child_dest = dest.join(entry.file_name());
            copy_recursive(&entry.path(), &child_dest)?;
        }
    } else {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(source, dest)?;
    }
    Ok(())
}

fn write_workspace_marker(lower: &Path, workspace_id: &str) -> anyhow::Result<()> {
    let marker_dir = lower.join(".lit");
    std::fs::create_dir_all(&marker_dir)?;
    let marker = marker_dir.join("workspace.json");
    let data = json!({ "workspace_id": workspace_id });
    std::fs::write(marker, serde_json::to_vec_pretty(&data)?)?;
    Ok(())
}

fn write_workspace_config(
    root: &Path,
    mountpoint: &Path,
    workspace_id: &str,
    lower: &Path,
    upper: &Path,
    work: &Path,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(root)?;
    let config_path = root.join("workspace.json");
    let payload = json!({
        "workspace_id": workspace_id,
        "mountpoint": mountpoint,
        "lower": lower,
        "upper": upper,
        "work": work
    });
    let mut file = File::create(config_path)?;
    file.write_all(serde_json::to_string_pretty(&payload)?.as_bytes())?;
    Ok(())
}

fn mount_overlay(mountpoint: &Path, lower: &Path, upper: &Path, work: &Path) -> anyhow::Result<()> {
    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    let status = Command::new("fuse-overlayfs")
        .arg("-o")
        .arg(opts)
        .arg(mountpoint)
        .spawn()
        .map_err(|e| anyhow!("failed to spawn fuse-overlayfs: {e}"))?;
    drop(status); // daemonizes on its own
    Ok(())
}
