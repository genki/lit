use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use dirs::home_dir;
use hex::ToHex;
use libc;
use lit_crdt::TextCrdt;
use mime_guess::MimeGuess;
use pathdiff::diff_paths;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::env;
use std::fs::File;
use std::io::{self, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
#[command(
    name = "lit",
    about = "lit CLI",
    subcommand_required = false,
    arg_required_else_help = false
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
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
    /// Add files/directories to watch list
    #[command(alias = "track")]
    Add(WatchArgs),
    /// Remove files/directories from watch list
    #[command(alias = "untrack")]
    Rm(WatchArgs),
    /// Show diff between lower snapshot and current workspace
    Log(LogArgs),
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

#[derive(clap::Args, Debug)]
struct WatchArgs {
    /// Files/directories to add/remove from tracking
    #[arg(required = true)]
    paths: Vec<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct LogArgs {
    /// Optional file/directory to inspect
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
        Some(Commands::Sync(args)) => run_sync(args).await?,
        Some(Commands::BlobFetch(args)) => run_blob_fetch(args).await?,
        Some(Commands::On(args)) => run_on(args).await?,
        Some(Commands::Off(args)) => run_off(args).await?,
        Some(Commands::Add(args)) => run_watch_args(args, true).await?,
        Some(Commands::Rm(args)) => run_watch_args(args, false).await?,
        Some(Commands::Log(args)) => run_log(args).await?,
        Some(Commands::Version) => run_version(),
        None => run_status().await?,
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

async fn run_status() -> anyhow::Result<()> {
    let target = std::env::current_dir()?;
    let canonical = fs::canonicalize(&target).await.unwrap_or(target.clone());
    match workspace_context_from_mount(canonical.clone()).await {
        Ok(ctx) => {
            let state = if is_path_mounted(&ctx.mountpoint)? {
                "ON"
            } else {
                "OFF"
            };
            println!("lit status: {}", state);
            println!(" workspace: {}", ctx.workspace_id);
            println!(" mountpoint: {}", ctx.mountpoint.display());
            println!(" lower: {}", ctx.root.join("lower").display());
            println!(" upper: {}", ctx.root.join("upper").display());
            let watch = load_watchlist(&ctx.root)?;
            if watch.is_empty() {
                println!(" tracked: (none)");
            } else {
                println!(" tracked:");
                for path in watch.into_iter().collect::<BTreeSet<_>>() {
                    println!("  {}", path);
                }
            }
        }
        Err(_) => {
            println!("lit: not initialized at {}", canonical.display());
        }
    }
    Ok(())
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
    let workspace_exists = workspace_root.exists();
    fs::create_dir_all(&lower).await?;
    fs::create_dir_all(&upper).await?;
    fs::create_dir_all(&work).await?;

    if !workspace_exists {
        save_watchlist(&workspace_root, &HashSet::new())?;
    }
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

    spawn_lit_fs_daemon(&lower, &canonical_target)?;
    wait_for_mount(&canonical_target).await?;
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
    let workspace_id = workspace_id(&canonical).await?;
    let workspace_root = lit_home_dir()?.join("workspaces").join(&workspace_id);
    if !workspace_root.exists() {
        return Err(anyhow!("{} is not a lit workspace", canonical.display()));
    }
    let lower = workspace_root.join("lower");
    sync_mountpoint_to_lower(&canonical, &lower)?;
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
    sync_lower_to_target(&lower, &canonical)?;
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

async fn wait_for_mount(path: &Path) -> anyhow::Result<()> {
    for _ in 0..20 {
        if is_path_mounted(path)? {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(anyhow!(
        "timed out waiting for fuse-overlayfs to mount {}",
        path.display()
    ))
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

struct WorkspaceContext {
    mountpoint: PathBuf,
    workspace_id: String,
    root: PathBuf,
}

async fn workspace_context_from_arg(path: Option<PathBuf>) -> anyhow::Result<WorkspaceContext> {
    let base = match path {
        Some(p) => p,
        None => std::env::current_dir()?,
    };
    let canonical = fs::canonicalize(&base).await.unwrap_or(base.clone());
    workspace_context_from_mount(canonical).await
}

async fn workspace_context_from_mount(mountpoint: PathBuf) -> anyhow::Result<WorkspaceContext> {
    let workspace_id = workspace_id(&mountpoint).await?;
    let root = lit_home_dir()?.join("workspaces").join(&workspace_id);
    if !root.exists() {
        Err(anyhow!("{} is not a lit workspace", mountpoint.display()))
    } else {
        Ok(WorkspaceContext {
            mountpoint,
            workspace_id,
            root,
        })
    }
}

fn move_existing_contents(source: &Path, lower: &Path) -> anyhow::Result<()> {
    if lower.exists() {
        std::fs::remove_dir_all(lower)?;
    }
    std::fs::create_dir_all(lower)?;
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

fn copy_dir_contents(src: &Path, dest: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let child_dest = dest.join(entry.file_name());
        copy_recursive(&entry.path(), &child_dest)?;
    }
    Ok(())
}

fn clear_directory_contents(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                std::fs::remove_dir_all(&entry_path)?;
            } else {
                std::fs::remove_file(&entry_path)?;
            }
        }
    } else {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

fn sync_lower_to_target(lower: &Path, target: &Path) -> anyhow::Result<()> {
    clear_directory_contents(target)?;
    copy_dir_contents(lower, target)
}

fn sync_mountpoint_to_lower(mountpoint: &Path, lower: &Path) -> anyhow::Result<()> {
    if lower.exists() {
        std::fs::remove_dir_all(lower)?;
    }
    copy_dir_contents(mountpoint, lower)
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

fn is_path_mounted(path: &Path) -> anyhow::Result<bool> {
    match Command::new("mountpoint").arg("-q").arg(path).status() {
        Ok(status) => Ok(status.success()),
        Err(_) => {
            let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
            let display = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
            Ok(mounts.contains(display.to_string_lossy().as_ref()))
        }
    }
}

fn spawn_lit_fs_daemon(source: &Path, mountpoint: &Path) -> anyhow::Result<()> {
    let bin = which::which("lit-fs").context("lit-fs binary not found")?;
    std::fs::create_dir_all(source)?;
    Command::new(bin)
        .arg("--source")
        .arg(source)
        .arg("--mountpoint")
        .arg(mountpoint)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| anyhow!("failed to spawn lit-fs: {e}"))
}

#[derive(Serialize, Deserialize, Default)]
struct WatchState {
    paths: Vec<String>,
}

fn watchlist_path(root: &Path) -> PathBuf {
    root.join("watch.json")
}

fn load_watchlist(root: &Path) -> anyhow::Result<HashSet<String>> {
    let path = watchlist_path(root);
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let bytes = std::fs::read(&path)?;
    let state: WatchState = serde_json::from_slice(&bytes)?;
    Ok(state.paths.into_iter().collect())
}

fn save_watchlist(root: &Path, watch: &HashSet<String>) -> anyhow::Result<()> {
    std::fs::create_dir_all(root)?;
    let mut entries: Vec<_> = watch.iter().cloned().collect();
    entries.sort();
    let state = WatchState { paths: entries };
    std::fs::write(watchlist_path(root), serde_json::to_vec_pretty(&state)?)?;
    Ok(())
}

async fn run_watch_args(args: WatchArgs, add: bool) -> anyhow::Result<()> {
    let ctx = workspace_context_from_arg(None).await?;
    let mut watch = load_watchlist(&ctx.root)?;
    for path in args.paths {
        let rel = relative_to_workspace(&path, &ctx.mountpoint).await?;
        if add {
            if watch.insert(rel.clone()) {
                println!("added {rel}");
            } else {
                println!("already tracking {rel}");
            }
        } else if watch.remove(&rel) {
            println!("removed {rel}");
        } else {
            println!("not tracked {rel}");
        }
    }
    save_watchlist(&ctx.root, &watch)?;
    Ok(())
}

async fn relative_to_workspace(path: &Path, mount: &Path) -> anyhow::Result<String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        mount.join(path)
    };
    let canonical = fs::canonicalize(&absolute)
        .await
        .with_context(|| format!("failed to resolve {}", absolute.display()))?;
    if !canonical.starts_with(mount) {
        return Err(anyhow!(
            "{} is outside the workspace {}",
            canonical.display(),
            mount.display()
        ));
    }
    let rel = diff_paths(&canonical, mount).ok_or_else(|| {
        anyhow!(
            "failed to compute relative path for {}",
            canonical.display()
        )
    })?;
    Ok(normalize_relative(&rel))
}

fn normalize_relative(path: &Path) -> String {
    let mut s = path.to_string_lossy().replace('\\', "/");
    if s.is_empty() {
        s = ".".to_string();
    }
    s
}

fn update_crdt_document(ctx: &WorkspaceContext, rel: &str) -> anyhow::Result<()> {
    let doc_path = crdt_doc_path(&ctx.root, rel);
    if let Some(parent) = doc_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = std::fs::read(&doc_path).unwrap_or_default();
    let mut doc = TextCrdt::load(&bytes)?;
    let target = ctx.mountpoint.join(rel);
    if target.is_dir() {
        return Ok(());
    }
    let contents = std::fs::read_to_string(&target).unwrap_or_default();
    doc.apply_text(&contents)?;
    std::fs::write(doc_path, doc.save())?;
    Ok(())
}

fn crdt_doc_path(root: &Path, rel: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(rel.as_bytes());
    let name = format!("{}.amrg", hex::encode(hasher.finalize()));
    root.join("crdt").join(name)
}

async fn run_log(args: LogArgs) -> anyhow::Result<()> {
    let ctx = workspace_context_from_arg(None).await?;
    let watch = load_watchlist(&ctx.root)?;
    let targets: Vec<String> = if let Some(path) = args.path {
        let rel = relative_to_workspace(&path, &ctx.mountpoint).await?;
        if !watch.contains(&rel) {
            println!(
                "lit log: {} is not tracked; use `lit add {}` first",
                rel, rel
            );
            return Ok(());
        }
        vec![rel]
    } else {
        watch.into_iter().collect()
    };
    if targets.is_empty() {
        println!("lit log: no tracked paths");
        return Ok(());
    }
    let mut output = String::new();
    for rel in targets {
        update_crdt_document(&ctx, &rel)?;
        let mount_path = ctx.mountpoint.join(&rel);
        let lower_path = ctx.root.join("lower").join(&rel);
        let diff = generate_diff(&lower_path, &mount_path)?;
        if diff.is_empty() {
            output.push_str(&format!("diff -- lit {rel}: no changes\n\n"));
        } else {
            output.push_str(&format!("diff -- lit {rel}\n"));
            output.push_str(&diff);
            if !diff.ends_with('\n') {
                output.push('\n');
            }
            output.push('\n');
        }
    }
    if output.is_empty() {
        output.push_str("lit log: no changes\n");
    }
    display_with_pager(&output)?;
    Ok(())
}

fn generate_diff(lower: &Path, mount: &Path) -> anyhow::Result<String> {
    let recursive = lower.is_dir() || mount.is_dir();
    let lower_arg = if lower.exists() {
        lower.to_path_buf()
    } else {
        PathBuf::from("/dev/null")
    };
    let mount_arg = if mount.exists() {
        mount.to_path_buf()
    } else {
        PathBuf::from("/dev/null")
    };
    let mut cmd = Command::new("diff");
    if recursive {
        cmd.arg("-urN");
    } else {
        cmd.arg("-u");
    }
    let output = cmd.arg(&lower_arg).arg(&mount_arg).output();
    match output {
        Ok(result) => match result.status.code() {
            Some(0) => Ok(String::new()),
            Some(1) | None => Ok(String::from_utf8_lossy(&result.stdout).to_string()),
            _ => Err(anyhow!("diff command failed")),
        },
        Err(_) => {
            if recursive {
                Ok(String::new())
            } else {
                let old = std::fs::read_to_string(&lower_arg).unwrap_or_default();
                let new = std::fs::read_to_string(&mount_arg).unwrap_or_default();
                if old == new {
                    Ok(String::new())
                } else {
                    Ok(format!(
                        "--- {}\n+++ {}\n@@\n-{}\n+{}\n",
                        lower_arg.display(),
                        mount_arg.display(),
                        old.trim_end(),
                        new.trim_end()
                    ))
                }
            }
        }
    }
}

fn display_with_pager(text: &str) -> anyhow::Result<()> {
    let pager = env::var("PAGER").unwrap_or_else(|_| String::from("less -R"));
    let mut parts = pager.split_whitespace();
    let cmd = parts.next().unwrap_or("less");
    let args: Vec<&str> = parts.collect();
    match Command::new(cmd).args(&args).stdin(Stdio::piped()).spawn() {
        Ok(mut child) => {
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(text.as_bytes())?;
            }
            child.wait()?;
        }
        Err(_) => {
            io::stdout().write_all(text.as_bytes())?;
        }
    }
    Ok(())
}
