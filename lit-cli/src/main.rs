use anyhow::{anyhow, Context};
use chrono::{Local, LocalResult, TimeZone};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
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
use std::path::{Component, Path, PathBuf};
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

mod mount;

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
    /// Tag operations (create or list)
    Tag(TagArgs),
    /// Reset workspace to a tagged state
    Reset(ResetArgs),
    /// Acquire a lock on a path
    Lock(LockArgs),
    /// Unlock a previously acquired lock
    Unlock(UnlockArgs),
    /// Drop files and purge their history
    Drop(DropArgs),
    /// Show diff between lower snapshot and current workspace
    Log(LogArgs),
    /// Show CLI version information
    Version,
    /// Generate shell completion scripts
    Completions(CompletionArgs),
}

#[derive(clap::Args, Debug, Clone)]
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
    /// 指定すると同期を周期実行
    #[arg(long)]
    repeat: Option<u64>,
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
    /// update shared(global) watch list instead of session-local
    #[arg(long)]
    global: bool,
}

#[derive(clap::Args, Debug)]
struct DropArgs {
    /// Files/directories to delete from workspace & history
    #[arg(required = true)]
    paths: Vec<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct LogArgs {
    /// Optional file/directory to inspect
    path: Option<PathBuf>,
    /// Continuously watch changes
    #[arg(long)]
    watch: bool,
    /// Interval seconds for --watch
    #[arg(long, default_value_t = 5)]
    interval: u64,
}

#[derive(clap::Args, Debug)]
struct CompletionArgs {
    /// Shell type to generate completions for
    #[arg(value_enum)]
    shell: Shell,
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
        Some(Commands::Tag(args)) => run_tag(args).await?,
        Some(Commands::Reset(args)) => run_reset(args).await?,
        Some(Commands::Lock(args)) => run_lock(args).await?,
        Some(Commands::Unlock(args)) => run_unlock(args).await?,
        Some(Commands::Drop(args)) => run_drop(args).await?,
        Some(Commands::Log(args)) => run_log(args).await?,
        Some(Commands::Completions(args)) => run_completions(args)?,
        Some(Commands::Version) => run_version(),
        None => run_status().await?,
    }
    Ok(())
}

async fn run_sync(args: SyncArgs) -> anyhow::Result<()> {
    if let Some(interval) = args.repeat {
        loop {
            run_sync_once(&args).await?;
            sleep(Duration::from_secs(interval)).await;
        }
    } else {
        run_sync_once(&args).await?;
    }
    Ok(())
}

fn run_completions(args: CompletionArgs) -> anyhow::Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(args.shell, &mut cmd, "lit", &mut io::stdout());
    Ok(())
}

async fn run_sync_once(args: &SyncArgs) -> anyhow::Result<()> {
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

    if let Some(path) = args.file.clone() {
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
            println!(" lower: {}", ctx.lower.display());
            println!(" upper: {}", ctx.upper.display());
            let session = session_id()?;
            let watchlists = load_watchlists(&ctx.root, &session)?;
            if watchlists.global.is_empty() && watchlists.session.is_empty() {
                println!(" tracked: (none)");
            } else {
                if !watchlists.global.is_empty() {
                    println!(" tracked (global):");
                    for path in watchlists.global.iter().cloned().collect::<BTreeSet<_>>() {
                        println!("  {}", path);
                    }
                }
                if !watchlists.session.is_empty() {
                    println!(" tracked (session {}):", session);
                    for path in watchlists.session.iter().cloned().collect::<BTreeSet<_>>() {
                        println!("  {}", path);
                    }
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
        save_watchlist_scope(&workspace_root, WatchScope::Global, &HashSet::new())?;
    }
    move_existing_contents(&canonical_target, &lower)?;
    write_workspace_marker(&lower, &workspace_id)?;
    hydrate_upper_from_lower(&lower, &upper)?;
    write_workspace_config(
        &workspace_root,
        &canonical_target,
        &workspace_id,
        &lower,
        &upper,
        &work,
    )?;

    let locks_file = workspace_root.join("locks.json");
    spawn_lit_fs_daemon(&upper, &canonical_target, &locks_file)?;
    mount::write_state(
        &workspace_root,
        &mount::MountState {
            lower: lower.clone(),
            mountpoint: canonical_target.clone(),
        },
    )?;
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
    let upper = workspace_root.join("upper");
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
    sync_upper_to_target(&upper, &canonical)?;
    mount::clear_state(&workspace_root)?;
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
    lower: PathBuf,
    upper: PathBuf,
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
        let lower = root.join("lower");
        let upper = root.join("upper");
        Ok(WorkspaceContext {
            mountpoint,
            workspace_id,
            root,
            lower,
            upper,
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

fn ensure_lower_snapshot(lower: &Path, target: &Path) -> anyhow::Result<()> {
    if lower.exists() && lower.read_dir()?.next().is_some() {
        // already has content
        return Ok(());
    }
    clear_directory_contents(lower)?;
    copy_dir_contents(target, lower)
}

fn copy_dir_contents(src: &Path, dest: &Path) -> anyhow::Result<()> {
    if !src.exists() {
        std::fs::create_dir_all(dest)?;
        return Ok(());
    }
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let child_dest = dest.join(entry.file_name());
        copy_recursive(&entry.path(), &child_dest)?;
    }
    Ok(())
}

fn ensure_lower_entry(lower_root: &Path, mount_root: &Path, rel: &str) -> anyhow::Result<()> {
    let src = mount_root.join(rel);
    let dst = lower_root.join(rel);
    if dst.exists() {
        return Ok(());
    }
    if src.is_dir() {
        copy_dir_contents(&src, &dst)
    } else if src.is_file() {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&src, &dst)?;
        Ok(())
    } else {
        Ok(())
    }
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

fn hydrate_upper_from_lower(lower: &Path, upper: &Path) -> anyhow::Result<()> {
    clear_directory_contents(upper)?;
    copy_dir_contents(lower, upper)
}

fn sync_upper_to_target(upper: &Path, target: &Path) -> anyhow::Result<()> {
    clear_directory_contents(target)?;
    copy_dir_contents(upper, target)
}

fn fallback_relative_path(path: &Path, mount: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        if path.starts_with(mount) {
            diff_paths(path, mount)
        } else {
            None
        }
    } else {
        Some(path.to_path_buf())
    }
}

fn drop_target(ctx: &WorkspaceContext, rel: &str) -> anyhow::Result<()> {
    remove_path(&ctx.mountpoint.join(rel))?;
    remove_path(&ctx.lower.join(rel))?;
    remove_path(&ctx.upper.join(rel))?;
    let crdt_doc = crdt_doc_path(&ctx.root, rel);
    if crdt_doc.exists() {
        std::fs::remove_file(crdt_doc)?;
    }
    Ok(())
}

fn remove_path(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() as u32 }
}

fn current_pid() -> u32 {
    std::process::id()
}

fn pid_alive(pid: u32) -> bool {
    let path = PathBuf::from(format!("/proc/{pid}"));
    path.exists()
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

fn spawn_lit_fs_daemon(source: &Path, mountpoint: &Path, locks_file: &Path) -> anyhow::Result<()> {
    let bin = which::which("lit-fs").context("lit-fs binary not found")?;
    std::fs::create_dir_all(source)?;
    Command::new(bin)
        .arg("--source")
        .arg(source)
        .arg("--mountpoint")
        .arg(mountpoint)
        .arg("--locks-file")
        .arg(locks_file)
        .spawn()
        .map(|_| ())
        .map_err(|e| anyhow!("failed to spawn lit-fs: {e}"))
}

#[derive(Serialize, Deserialize, Default)]
struct WatchState {
    paths: Vec<String>,
}

struct WatchLists {
    global: HashSet<String>,
    session: HashSet<String>,
}

enum WatchScope<'a> {
    Global,
    Session(&'a str),
}

fn load_watchlists(root: &Path, session: &str) -> anyhow::Result<WatchLists> {
    let global = load_watchlist_file(&watchlist_path(root))?;
    let session_set = load_watchlist_file(&watch_session_path(root, session))?;
    Ok(WatchLists {
        global,
        session: session_set,
    })
}

fn save_watchlist_scope(
    root: &Path,
    scope: WatchScope,
    watch: &HashSet<String>,
) -> anyhow::Result<()> {
    match scope {
        WatchScope::Global => save_watchlist_file(&watchlist_path(root), watch),
        WatchScope::Session(session) => {
            save_watchlist_file(&watch_session_path(root, session), watch)
        }
    }
}

fn combined_watchlist(lists: &WatchLists) -> HashSet<String> {
    let mut set = lists.global.clone();
    set.extend(lists.session.iter().cloned());
    set
}

fn session_id() -> anyhow::Result<String> {
    if let Ok(value) = env::var("LIT_SESSION_ID") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let path = lit_home_dir()?.join("session-id");
    if path.exists() {
        let contents = std::fs::read_to_string(&path)?;
        let trimmed = contents.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let generated = format!("default-{}", Uuid::new_v4());
    std::fs::write(&path, &generated)?;
    Ok(generated)
}

#[derive(Serialize, Deserialize)]
struct TagMetadata {
    name: String,
    message: Option<String>,
    created_at: i64,
}

#[derive(Serialize, Deserialize, Default)]
struct LocksState {
    locks: Vec<LockEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct LockEntry {
    path: String,
    owner_uid: u32,
    owner_pid: u32,
    message: Option<String>,
    created_at: i64,
    expires_at: Option<i64>,
    #[serde(default)]
    owner_session: String,
}

impl LockEntry {
    fn is_expired(&self, now: i64) -> bool {
        self.expires_at.map(|exp| now > exp).unwrap_or(false)
    }
}

fn watchlist_path(root: &Path) -> PathBuf {
    root.join("watch.json")
}

fn watch_session_dir(root: &Path) -> PathBuf {
    root.join("watch")
}

fn watch_session_path(root: &Path, session: &str) -> PathBuf {
    watch_session_dir(root).join(format!("{session}.json"))
}

fn load_watchlist_file(path: &Path) -> anyhow::Result<HashSet<String>> {
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let bytes = std::fs::read(path)?;
    let state: WatchState = serde_json::from_slice(&bytes)?;
    Ok(state.paths.into_iter().collect())
}

fn save_watchlist_file(path: &Path, watch: &HashSet<String>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut entries: Vec<_> = watch.iter().cloned().collect();
    entries.sort();
    let state = WatchState { paths: entries };
    std::fs::write(path, serde_json::to_vec_pretty(&state)?)?;
    Ok(())
}

fn lock_state_path(root: &Path) -> PathBuf {
    root.join("locks.json")
}

fn load_locks(root: &Path) -> anyhow::Result<LocksState> {
    let path = lock_state_path(root);
    if !path.exists() {
        return Ok(LocksState::default());
    }
    let bytes = std::fs::read(&path)?;
    let mut state: LocksState = serde_json::from_slice(&bytes)?;
    let now = unix_timestamp();
    if prune_expired_locks(&mut state, now) {
        save_locks(root, &state)?;
    }
    Ok(state)
}

fn prune_expired_locks(state: &mut LocksState, now: i64) -> bool {
    let before = state.locks.len();
    state.locks.retain(|entry| !entry.is_expired(now));
    before != state.locks.len()
}

fn save_locks(root: &Path, state: &LocksState) -> anyhow::Result<()> {
    std::fs::create_dir_all(root)?;
    let path = lock_state_path(root);
    std::fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}

fn tags_root(root: &Path) -> PathBuf {
    root.join("tags")
}

fn tag_dir(root: &Path, name: &str) -> PathBuf {
    tags_root(root).join(name)
}

fn tag_tree_path(root: &Path, name: &str) -> PathBuf {
    tag_dir(root, name).join("tree")
}

fn write_tag_metadata(dir: &Path, meta: &TagMetadata) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let meta_path = dir.join("meta.json");
    std::fs::write(meta_path, serde_json::to_vec_pretty(meta)?)?;
    Ok(())
}

fn read_tag_metadata(dir: &Path) -> anyhow::Result<TagMetadata> {
    let meta_path = dir.join("meta.json");
    let bytes = std::fs::read(meta_path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn list_tags(root: &Path) -> anyhow::Result<()> {
    let tags_dir = tags_root(root);
    if !tags_dir.exists() {
        println!("(no tags)");
        return Ok(());
    }
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(tags_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Ok(meta) = read_tag_metadata(&entry.path()) {
                entries.push(meta);
            }
        }
    }
    if entries.is_empty() {
        println!("(no tags)");
        return Ok(());
    }
    entries.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    for meta in entries {
        let ts = format_timestamp(meta.created_at);
        let message = meta.message.unwrap_or_default();
        if message.is_empty() {
            println!("{} {}", ts, meta.name);
        } else {
            println!("{} {} {}", ts, meta.name, message);
        }
    }
    Ok(())
}

fn validate_tag_name(name: &str) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("tag name cannot be empty"));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(anyhow!("tag name cannot contain path separators"));
    }
    if name == "." || name == ".." {
        return Err(anyhow!("tag name {} is invalid", name));
    }
    Ok(())
}

fn format_timestamp(ts: i64) -> String {
    if ts <= 0 {
        return "-".into();
    }
    match Local.timestamp_opt(ts, 0) {
        LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        _ => ts.to_string(),
    }
}

fn list_locks(root: &Path) -> anyhow::Result<()> {
    let state = load_locks(root)?;
    if state.locks.is_empty() {
        println!("(no locks)");
        return Ok(());
    }
    let mut entries = state.locks.clone();
    entries.sort_by(|a, b| a.path.cmp(&b.path).then(a.created_at.cmp(&b.created_at)));
    for entry in entries {
        let created = format_timestamp(entry.created_at);
        let mut line = format!(
            "{} {} uid={} pid={}",
            created, entry.path, entry.owner_uid, entry.owner_pid
        );
        if let Some(msg) = entry.message.as_deref() {
            if !msg.is_empty() {
                line.push(' ');
                line.push_str(msg);
            }
        }
        if let Some(exp) = entry.expires_at {
            line.push_str(&format!(" (expires {})", format_timestamp(exp)));
        }
        if !entry.owner_session.is_empty() {
            line.push_str(&format!(" session={}", entry.owner_session));
        }
        println!("{}", line);
    }
    Ok(())
}

fn ensure_session_exclusive(ctx: &WorkspaceContext) -> anyhow::Result<()> {
    let session = session_id()?;
    let state = load_locks(&ctx.root)?;
    let now = unix_timestamp();
    for entry in state.locks {
        if entry.is_expired(now) {
            continue;
        }
        if entry.owner_session.is_empty() || entry.owner_session == session {
            continue;
        }
        return Err(anyhow!(
            "lock held by session {} on {}; aborting",
            entry.owner_session,
            entry.path
        ));
    }
    Ok(())
}

async fn run_watch_args(args: WatchArgs, add: bool) -> anyhow::Result<()> {
    let ctx = workspace_context_from_arg(None).await?;
    let session = session_id()?;
    let mut lists = load_watchlists(&ctx.root, &session)?;
    let target = if args.global {
        &mut lists.global
    } else {
        &mut lists.session
    };
    for path in args.paths {
        let rel = relative_to_workspace(&path, &ctx.mountpoint).await?;
        if add {
            ensure_lower_entry(&ctx.lower, &ctx.mountpoint, &rel)?;
            if target.insert(rel.clone()) {
                println!("added {rel}");
            } else {
                println!("already tracking {rel}");
            }
        } else if target.remove(&rel) {
            println!("removed {rel}");
        } else {
            println!("not tracked {rel}");
        }
    }
    let scope = if args.global {
        WatchScope::Global
    } else {
        WatchScope::Session(&session)
    };
    save_watchlist_scope(&ctx.root, scope, target)?;
    Ok(())
}

async fn run_tag(args: TagArgs) -> anyhow::Result<()> {
    let ctx = workspace_context_from_arg(None).await?;
    if let Some(name) = args.name {
        ensure_session_exclusive(&ctx)?;
        validate_tag_name(&name)?;
        let tag_dir = tag_dir(&ctx.root, &name);
        if tag_dir.exists() {
            return Err(anyhow!("tag {} already exists", name));
        }
        let tree_path = tag_tree_path(&ctx.root, &name);
        clear_directory_contents(&tree_path)?;
        copy_dir_contents(&ctx.mountpoint, &tree_path)?;
        let metadata = TagMetadata {
            name: name.clone(),
            message: if args.message.is_empty() {
                None
            } else {
                Some(args.message.join(" "))
            },
            created_at: unix_timestamp(),
        };
        write_tag_metadata(&tag_dir, &metadata)?;
        println!("created tag {}", name);
    } else {
        list_tags(&ctx.root)?;
    }
    Ok(())
}

async fn run_reset(args: ResetArgs) -> anyhow::Result<()> {
    let ctx = workspace_context_from_arg(None).await?;
    ensure_session_exclusive(&ctx)?;
    validate_tag_name(&args.name)?;
    let tree_path = tag_tree_path(&ctx.root, &args.name);
    if !tree_path.exists() {
        return Err(anyhow!("tag {} not found", args.name));
    }
    clear_directory_contents(&ctx.upper)?;
    copy_dir_contents(&tree_path, &ctx.upper)?;
    clear_directory_contents(&ctx.lower)?;
    copy_dir_contents(&tree_path, &ctx.lower)?;
    println!("reset to tag {}", args.name);
    Ok(())
}

async fn run_lock(args: LockArgs) -> anyhow::Result<()> {
    let ctx = workspace_context_from_arg(None).await?;
    let session = session_id()?;
    if let Some(path) = args.path {
        let rel = relative_to_workspace(&path, &ctx.mountpoint).await?;
        let mut state = load_locks(&ctx.root)?;
        let now = unix_timestamp();
        let expired_removed = prune_expired_locks(&mut state, now);
        if let Some(existing) = state
            .locks
            .iter()
            .find(|entry| entry.path == rel && !entry.is_expired(now))
        {
            let locker_alive = pid_alive(existing.owner_pid);
            let same_session =
                !existing.owner_session.is_empty() && existing.owner_session == session;
            if existing.owner_uid == current_uid() {
                if same_session {
                    if existing.owner_pid != current_pid() && locker_alive {
                        let msg = existing
                            .message
                            .as_deref()
                            .unwrap_or("locked by another process");
                        return Err(anyhow!(
                            "{} is already locked by session {} (pid {} still active): {}",
                            rel,
                            existing.owner_session,
                            existing.owner_pid,
                            msg
                        ));
                    }
                } else if locker_alive {
                    let msg = existing
                        .message
                        .as_deref()
                        .unwrap_or("locked by another process");
                    let owner_session = if existing.owner_session.is_empty() {
                        "<unknown>"
                    } else {
                        &existing.owner_session
                    };
                    return Err(anyhow!(
                        "{} is locked by uid {} session {} pid {}: {}",
                        rel,
                        existing.owner_uid,
                        owner_session,
                        existing.owner_pid,
                        msg
                    ));
                }
            } else if locker_alive {
                let msg = existing
                    .message
                    .as_deref()
                    .unwrap_or("locked by another process");
                return Err(anyhow!(
                    "{} is locked by uid {} pid {}: {}",
                    rel,
                    existing.owner_uid,
                    existing.owner_pid,
                    msg
                ));
            }
        }
        let expires_at = args.timeout.filter(|t| *t > 0).map(|t| now + t as i64);
        let entry = LockEntry {
            path: rel.clone(),
            owner_uid: current_uid(),
            owner_pid: current_pid(),
            message: args.message.clone(),
            created_at: now,
            expires_at,
            owner_session: session.clone(),
        };
        state.locks.retain(|e| e.path != rel);
        state.locks.push(entry);
        save_locks(&ctx.root, &state)?;
        if expired_removed {
            println!("expired locks were cleaned up");
        }
        println!(
            "locked {} (uid={} pid={})",
            rel,
            current_uid(),
            current_pid()
        );
    } else {
        list_locks(&ctx.root)?;
    }
    Ok(())
}

async fn run_unlock(args: UnlockArgs) -> anyhow::Result<()> {
    let ctx = workspace_context_from_arg(None).await?;
    let rel = relative_to_workspace(&args.path, &ctx.mountpoint).await?;
    let mut state = load_locks(&ctx.root)?;
    let current_uid = current_uid();
    let current_pid = current_pid();
    let mut removed = false;
    state.locks.retain(|entry| {
        if entry.path != rel {
            return true;
        }
        if entry.owner_uid != current_uid {
            return true;
        }
        if entry.owner_pid == current_pid {
            removed = true;
            return false;
        }
        if !pid_alive(entry.owner_pid) {
            removed = true;
            return false;
        }
        true
    });
    if !removed {
        return Err(anyhow!(
            "no lock held by uid={} on {} (locker pid still running)",
            current_uid,
            rel
        ));
    }
    save_locks(&ctx.root, &state)?;
    println!("unlocked {}", rel);
    Ok(())
}

async fn run_drop(args: DropArgs) -> anyhow::Result<()> {
    let ctx = workspace_context_from_arg(None).await?;
    let session = session_id()?;
    let mut watchlists = load_watchlists(&ctx.root, &session)?;
    let mut watch_changed = false;
    for path in args.paths {
        let rel = match relative_to_workspace(&path, &ctx.mountpoint).await {
            Ok(rel) => rel,
            Err(err) => {
                let fallback =
                    fallback_relative_path(&path, &ctx.mountpoint).map(|p| normalize_relative(&p));
                if let Some(candidate) = fallback {
                    if watchlists.session.contains(&candidate)
                        || watchlists.global.contains(&candidate)
                        || ctx.lower.join(&candidate).exists()
                        || ctx.upper.join(&candidate).exists()
                    {
                        candidate
                    } else {
                        return Err(err);
                    }
                } else {
                    return Err(err);
                }
            }
        };
        drop_target(&ctx, &rel)?;
        if watchlists.session.remove(&rel) || watchlists.global.remove(&rel) {
            watch_changed = true;
        }
        println!("dropped {}", rel);
    }
    if watch_changed {
        save_watchlist_scope(
            &ctx.root,
            WatchScope::Session(&session),
            &watchlists.session,
        )?;
        save_watchlist_scope(&ctx.root, WatchScope::Global, &watchlists.global)?;
    }
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
    let mut segments: Vec<String> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if segments.is_empty() {
                    segments.push("..".to_string());
                } else {
                    segments.pop();
                }
            }
            Component::Normal(part) => segments.push(part.to_string_lossy().replace('\\', "/")),
            Component::RootDir => {}
            Component::Prefix(prefix) => {
                segments.push(prefix.as_os_str().to_string_lossy().replace('\\', "/"))
            }
        }
    }
    if segments.is_empty() {
        ".".to_string()
    } else {
        segments.join("/")
    }
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
    let session = session_id()?;
    let watchlists = load_watchlists(&ctx.root, &session)?;
    ensure_lower_snapshot(&ctx.lower, &ctx.mountpoint)?;
    let base_watch = combined_watchlist(&watchlists);
    let targets: Vec<String> = if let Some(path) = args.path {
        let rel = relative_to_workspace(&path, &ctx.mountpoint).await?;
        if !base_watch.contains(&rel) {
            println!(
                "lit log: {} is not tracked; use `lit add {}` first",
                rel, rel
            );
            return Ok(());
        }
        vec![rel]
    } else {
        base_watch.into_iter().collect()
    };
    if targets.is_empty() {
        println!("lit log: no tracked paths");
        return Ok(());
    }
    if args.watch {
        loop {
            let output = build_log_output(&ctx, &targets)?;
            println!(
                "== lit log @ {} ==\n{}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                output
            );
            sleep(Duration::from_secs(args.interval)).await;
        }
    } else {
        let output = build_log_output(&ctx, &targets)?;
        display_with_pager(&output)?;
    }
    Ok(())
}

fn build_log_output(ctx: &WorkspaceContext, targets: &[String]) -> anyhow::Result<String> {
    let mut output = String::new();
    for rel in targets {
        update_crdt_document(ctx, rel)?;
        ensure_lower_entry(&ctx.lower, &ctx.mountpoint, rel)?;
        let mount_path = ctx.mountpoint.join(rel);
        let lower_path = ctx.lower.join(rel);
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
    Ok(output)
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
#[derive(clap::Args, Debug)]
struct TagArgs {
    /// 作成するタグ名（省略時はタグ一覧を表示）
    name: Option<String>,
    /// 任意のメッセージ（タグ作成時のみ）
    #[arg(num_args = 0.., trailing_var_arg = true)]
    message: Vec<String>,
}

#[derive(clap::Args, Debug)]
struct ResetArgs {
    /// 巻き戻すタグ名
    name: String,
}

#[derive(clap::Args, Debug)]
struct LockArgs {
    /// ロック対象（省略時は一覧表示）
    path: Option<PathBuf>,
    /// ロックの有効期限（秒）
    #[arg(long)]
    timeout: Option<u64>,
    /// ロック理由のメッセージ
    #[arg(short = 'm', long = "message")]
    message: Option<String>,
}

#[derive(clap::Args, Debug)]
struct UnlockArgs {
    /// 解除対象パス
    path: PathBuf,
}
