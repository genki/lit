use anyhow::{anyhow, Context};
use chrono::{Local, LocalResult, TimeZone, Utc};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use dirs::home_dir;
use hex::ToHex;
use libc;
use lit_crdt::TextCrdt;
use pathdiff::diff_paths;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fs::File;
use std::io::{self, Write as IoWrite};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tonic::Request;
use tracing::{info, warn};
use uuid::Uuid;

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::ffi::{CStr, CString};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::ffi::OsStrExt;

use proto::relay_service_client::RelayServiceClient;
use proto::{
    FetchSnapshotRequest, ListWorkspacesRequest, PublishSnapshotRequest, SnapshotEnvelope,
    SubscribeSnapshotsRequest,
};
use state_sync::{
    apply_incoming_snapshots, apply_snapshot, archive_remote_snapshot, build_snapshot,
    latest_remote_version, persist_local_snapshot, WorkspaceSnapshot,
};

mod proto {
    tonic::include_proto!("lit.relay.v1");
}

mod mount;
mod state_sync;

const DEFAULT_RELAY_ADDR: &str = "127.0.0.1:5151";
const DIRTY_POLL_INTERVAL_MS: u64 = 500;
const DIRTY_COALESCE_SECS: u64 = 2;

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
    /// Show status for specific path
    Info(InfoArgs),
    /// List local/remote lit workspaces
    Ls(LsArgs),
    /// Clone a workspace from relay
    Clone(CloneArgs),
    /// Start local relay or remote sync
    Start(StartArgs),
    /// Stop relay/sync daemons
    Stop,
    /// Run daemon tasks (internal)
    #[command(hide = true)]
    Daemon(DaemonArgs),
    /// Show CLI version information
    Version,
    /// Generate shell completion scripts
    Completions(CompletionArgs),
}

#[derive(clap::Args, Debug, Clone)]
struct SyncArgs {
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    remote: String,
    #[arg(long, value_name = "PATH")]
    workspace: PathBuf,
    /// 指定すると同期を周期実行
    #[arg(long)]
    repeat: Option<u64>,
}

#[derive(clap::Args, Debug)]
struct OnArgs {
    /// Target directory to initialize (defaults to current directory)
    path: Option<PathBuf>,
    /// Use VM config JSON to mount via remote VM instead of local FUSE
    #[arg(long = "vm-config")]
    vm_config: Option<PathBuf>,
    /// Workspace slug (defaults to basename of path)
    #[arg(long = "name")]
    name: Option<String>,
}

#[derive(clap::Args, Debug)]
struct OffArgs {
    /// Targetディレクトリ(省略時はカレント)
    path: Option<PathBuf>,
    /// Use VM config JSON when unmounting remote VM workspace
    #[arg(long = "vm-config")]
    vm_config: Option<PathBuf>,
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

#[derive(clap::Args, Debug)]
struct InfoArgs {
    /// Path to inspect
    path: PathBuf,
}

#[derive(clap::Args, Debug)]
struct LsArgs {
    /// Relay URL to query for remote workspaces
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    remote: String,
    /// Only show local workspaces (skip relay call)
    #[arg(long)]
    local_only: bool,
}

#[derive(clap::Args, Debug)]
struct CloneArgs {
    /// Workspace slug to clone from relay
    workspace: String,
    /// Target path (defaults to workspace slug)
    path: Option<PathBuf>,
    /// Relay URL to fetch from
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    remote: String,
}

#[derive(clap::Args, Debug)]
struct StartArgs {
    /// Optional remote URL to sync with
    url: Option<String>,
}

#[derive(clap::Args, Debug)]
struct DaemonArgs {
    #[arg(value_enum)]
    mode: DaemonMode,
    #[arg(long)]
    remote: Option<String>,
    #[arg(long, default_value_t = 60)]
    interval: u64,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum DaemonMode {
    Sync,
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
        Some(Commands::Info(args)) => run_info(args).await?,
        Some(Commands::Ls(args)) => run_ls(args).await?,
        Some(Commands::Clone(args)) => run_clone(args).await?,
        Some(Commands::Start(args)) => run_start(args).await?,
        Some(Commands::Stop) => run_stop().await?,
        Some(Commands::Daemon(args)) => run_daemon(args).await?,
        Some(Commands::Completions(args)) => run_completions(args)?,
        Some(Commands::Version) => run_version(),
        None => run_status(None).await?,
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

async fn run_info(args: InfoArgs) -> anyhow::Result<()> {
    run_status(Some(args.path)).await
}

async fn run_clone(args: CloneArgs) -> anyhow::Result<()> {
    let slug = sanitize_slug(&args.workspace)?;
    let target = args.path.clone().unwrap_or_else(|| PathBuf::from(&slug));
    prepare_clone_target(&target)?;
    let mut client = relay_client(&args.remote).await?;
    let resp = client
        .fetch_snapshot(Request::new(FetchSnapshotRequest {
            workspace: slug.clone(),
        }))
        .await?
        .into_inner();
    let snapshot: WorkspaceSnapshot = serde_json::from_slice(&resp.snapshot_json)?;
    apply_snapshot(&target, &snapshot)?;
    println!(
        "lit clone: downloaded {} version {} into {}",
        slug,
        resp.stored_version,
        target.display()
    );
    let on_args = OnArgs {
        path: Some(target.clone()),
        vm_config: None,
        name: Some(slug),
    };
    run_on(on_args).await?;
    Ok(())
}

fn prepare_clone_target(target: &Path) -> anyhow::Result<()> {
    if target.exists() {
        if target.is_file() {
            return Err(anyhow!("clone target {} is a file", target.display()));
        }
        if std::fs::read_dir(target)?.next().is_some() {
            return Err(anyhow!("clone target {} must be empty", target.display()));
        }
    } else {
        std::fs::create_dir_all(target)?;
    }
    Ok(())
}

async fn run_start(args: StartArgs) -> anyhow::Result<()> {
    let mut state = load_daemon_state()?;
    if let Some(pid) = state.relay_pid {
        if !process_alive(pid) {
            state.relay_pid = None;
        }
    }
    if let Some(pid) = state.sync_pid {
        if !process_alive(pid) {
            state.sync_pid = None;
            state.sync_remote = None;
        }
    }

    match args.url {
        Some(url) => {
            if let Some(pid) = state.sync_pid {
                if process_alive(pid) {
                    println!(
                        "lit: sync daemon already running (pid {}) targeting {}",
                        pid,
                        state.sync_remote.as_deref().unwrap_or("unknown")
                    );
                    return Ok(());
                }
            }
            let exe = std::env::current_exe()?;
            let child = Command::new(exe)
                .arg("daemon")
                .arg("--mode")
                .arg("sync")
                .arg("--remote")
                .arg(&url)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .context("failed to start sync daemon")?;
            state.sync_pid = Some(child.id());
            state.sync_remote = Some(url.clone());
            save_daemon_state(&state)?;
            println!("lit: sync daemon started (pid {})", child.id());
        }
        None => {
            if let Some(pid) = state.relay_pid {
                if process_alive(pid) {
                    println!(
                        "lit: relay already running at {} (pid {})",
                        state.relay_addr.as_deref().unwrap_or(DEFAULT_RELAY_ADDR),
                        pid
                    );
                    return Ok(());
                }
            }
            let storage = lit_home_dir()?.join("relay");
            std::fs::create_dir_all(&storage)?;
            let addr = state
                .relay_addr
                .clone()
                .unwrap_or_else(|| DEFAULT_RELAY_ADDR.to_string());
            let child = Command::new("lit-relay")
                .arg("--listen")
                .arg(&addr)
                .arg("--storage-root")
                .arg(&storage)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .context("failed to start lit-relay")?;
            state.relay_pid = Some(child.id());
            state.relay_addr = Some(addr);
            state.relay_storage = Some(storage);
            save_daemon_state(&state)?;
            println!("lit: relay started (pid {})", child.id());
        }
    }
    Ok(())
}

async fn run_stop() -> anyhow::Result<()> {
    let mut state = load_daemon_state()?;
    if let Some(pid) = state.sync_pid {
        if process_alive(pid) {
            match terminate_process(pid) {
                Ok(_) => println!("lit: stopped sync daemon pid {pid}"),
                Err(err) => eprintln!("lit: failed to stop sync daemon: {err}"),
            }
        }
        state.sync_pid = None;
        state.sync_remote = None;
    }
    if let Some(pid) = state.relay_pid {
        if process_alive(pid) {
            match terminate_process(pid) {
                Ok(_) => println!("lit: stopped relay pid {pid}"),
                Err(err) => eprintln!("lit: failed to stop relay: {err}"),
            }
        }
        state.relay_pid = None;
        state.relay_addr = None;
        state.relay_storage = None;
    }
    save_daemon_state(&state)?;
    Ok(())
}

async fn run_daemon(args: DaemonArgs) -> anyhow::Result<()> {
    match args.mode {
        DaemonMode::Sync => {
            let remote = args
                .remote
                .ok_or_else(|| anyhow!("--remote is required for sync daemon"))?;
            daemon_sync_loop(remote, args.interval).await?
        }
    }
    Ok(())
}

struct SnapshotStreamPublisher {
    sender: mpsc::Sender<PublishSnapshotRequest>,
}

impl SnapshotStreamPublisher {
    async fn connect(remote: &str) -> anyhow::Result<Self> {
        let mut client = relay_client(remote).await?;
        let (tx, rx) = mpsc::channel(32);
        let stream = ReceiverStream::new(rx);
        let mut responses = client
            .publish_snapshot_stream(stream)
            .await
            .context("failed to open publish snapshot stream")?
            .into_inner();
        tokio::spawn(async move {
            loop {
                match responses.message().await {
                    Ok(Some(ack)) => info!(
                        workspace = %ack.workspace,
                        version = ack.stored_version,
                        "publish stream acknowledged snapshot"
                    ),
                    Ok(None) => {
                        warn!("publish snapshot stream completed");
                        break;
                    }
                    Err(status) => {
                        warn!("publish snapshot stream error: {status}");
                        break;
                    }
                }
            }
        });
        Ok(Self { sender: tx })
    }

    async fn publish(&self, req: PublishSnapshotRequest) -> anyhow::Result<()> {
        self.sender
            .send(req)
            .await
            .context("publish snapshot stream closed")?;
        Ok(())
    }
}

struct DirtyWorkspaceWatcher {
    ctx: WorkspaceContext,
    flag_path: PathBuf,
    last_mtime: Option<SystemTime>,
    last_signal_at: Option<Instant>,
}

impl DirtyWorkspaceWatcher {
    fn new(ctx: WorkspaceContext) -> Self {
        let flag_path = dirty_flag_path(&ctx.root);
        ensure_dirty_flag_file(&flag_path);
        Self {
            ctx,
            flag_path,
            last_mtime: None,
            last_signal_at: None,
        }
    }

    fn refresh_context(&mut self, ctx: WorkspaceContext) {
        self.ctx = ctx;
        self.flag_path = dirty_flag_path(&self.ctx.root);
        ensure_dirty_flag_file(&self.flag_path);
    }

    fn poll_flag(&mut self) {
        match std::fs::metadata(&self.flag_path) {
            Ok(meta) => {
                if let Ok(modified) = meta.modified() {
                    let newer = self.last_mtime.map(|prev| modified > prev).unwrap_or(true);
                    if newer {
                        self.last_mtime = Some(modified);
                        self.last_signal_at = Some(Instant::now());
                    }
                }
            }
            Err(_) => {}
        }
    }

    fn should_flush(&self, window: Duration) -> bool {
        self.last_signal_at
            .map(|instant| instant.elapsed() >= window)
            .unwrap_or(false)
    }

    fn mark_flushed(&mut self) {
        self.last_signal_at = None;
    }

    fn defer(&mut self) {
        self.last_signal_at = Some(Instant::now());
    }
}

struct DirtyWorkspaceManager {
    watchers: HashMap<String, DirtyWorkspaceWatcher>,
    coalesce: Duration,
}

impl DirtyWorkspaceManager {
    fn new(coalesce: Duration) -> Self {
        Self {
            watchers: HashMap::new(),
            coalesce,
        }
    }

    fn refresh(&mut self, contexts: &[WorkspaceContext]) {
        let active: HashSet<String> = contexts.iter().map(|c| c.slug.clone()).collect();
        self.watchers.retain(|slug, _| active.contains(slug));
        for ctx in contexts {
            self.watchers
                .entry(ctx.slug.clone())
                .and_modify(|watcher| watcher.refresh_context(ctx.clone()))
                .or_insert_with(|| DirtyWorkspaceWatcher::new(ctx.clone()));
        }
    }

    fn poll_flags(&mut self) {
        for watcher in self.watchers.values_mut() {
            watcher.poll_flag();
        }
    }

    async fn flush_due(&mut self, publisher: &SnapshotStreamPublisher) -> anyhow::Result<()> {
        let ready: Vec<String> = self
            .watchers
            .iter()
            .filter_map(|(id, watcher)| {
                if watcher.should_flush(self.coalesce) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for slug in ready {
            if let Some(watcher) = self.watchers.get_mut(&slug) {
                match is_path_mounted(&watcher.ctx.mountpoint) {
                    Ok(false) => {
                        watcher.defer();
                        continue;
                    }
                    Err(err) => {
                        warn!(
                            workspace = %watcher.ctx.slug,
                            "mount check failed: {err}"
                        );
                        watcher.defer();
                        continue;
                    }
                    Ok(true) => {}
                }
                match publish_workspace_snapshot(&watcher.ctx, publisher).await {
                    Ok(_) => watcher.mark_flushed(),
                    Err(err) => {
                        warn!(
                            workspace = %watcher.ctx.slug,
                            "failed to publish snapshot: {err}"
                        );
                        watcher.defer();
                    }
                }
            }
        }
        Ok(())
    }
}

struct RemoteSnapshotManager {
    remote: String,
    tasks: HashMap<String, JoinHandle<()>>,
}

impl RemoteSnapshotManager {
    fn new(remote: String) -> Self {
        Self {
            remote,
            tasks: HashMap::new(),
        }
    }

    async fn reconcile(&mut self, contexts: &[WorkspaceContext]) {
        let active: HashSet<String> = contexts.iter().map(|c| c.slug.clone()).collect();
        let mut to_remove = Vec::new();
        for key in self.tasks.keys() {
            if !active.contains(key) {
                to_remove.push(key.clone());
            }
        }
        for key in to_remove {
            if let Some(handle) = self.tasks.remove(&key) {
                handle.abort();
            }
        }
        for ctx in contexts {
            if self.tasks.contains_key(&ctx.slug) {
                continue;
            }
            let remote = self.remote.clone();
            let ctx_clone = ctx.clone();
            let handle = tokio::spawn(async move {
                if let Err(err) = run_remote_subscription(remote, ctx_clone).await {
                    warn!("remote subscribe task stopped: {err}");
                }
            });
            self.tasks.insert(ctx.slug.clone(), handle);
        }
    }
}

async fn daemon_sync_loop(remote: String, interval: u64) -> anyhow::Result<()> {
    let publisher = SnapshotStreamPublisher::connect(&remote).await?;
    let mut dirty_manager = DirtyWorkspaceManager::new(Duration::from_secs(DIRTY_COALESCE_SECS));
    let mut remote_manager = RemoteSnapshotManager::new(remote.clone());
    let mut contexts = discover_active_workspaces().await?;
    dirty_manager.refresh(&contexts);
    remote_manager.reconcile(&contexts).await;
    let rescan_interval = Duration::from_secs(interval.max(1));
    let mut last_rescan = Instant::now();
    loop {
        if last_rescan.elapsed() >= rescan_interval {
            contexts = discover_active_workspaces().await?;
            dirty_manager.refresh(&contexts);
            remote_manager.reconcile(&contexts).await;
            last_rescan = Instant::now();
        }
        dirty_manager.poll_flags();
        if let Err(err) = dirty_manager.flush_due(&publisher).await {
            warn!("lit daemon: flush error: {err}");
        }
        sleep(Duration::from_millis(DIRTY_POLL_INTERVAL_MS)).await;
    }
}

fn list_workspace_mountpoints() -> anyhow::Result<Vec<PathBuf>> {
    let mut mounts = Vec::new();
    let root = lit_home_dir()?.join("workspaces");
    if !root.exists() {
        return Ok(mounts);
    }
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.path().is_dir() {
            continue;
        }
        if let Some(vm_state) = read_vm_state(&entry.path())? {
            mounts.push(vm_state.mountpoint);
            continue;
        }
        let meta_path = entry.path().join("workspace.json");
        if !meta_path.exists() {
            continue;
        }
        let bytes = std::fs::read(&meta_path)?;
        if let Ok(cfg) = serde_json::from_slice::<WorkspaceConfig>(&bytes) {
            mounts.push(cfg.mountpoint);
        }
    }
    Ok(mounts)
}

async fn discover_active_workspaces() -> anyhow::Result<Vec<WorkspaceContext>> {
    let mounts = list_workspace_mountpoints()?;
    let mut contexts = Vec::new();
    for mount in mounts {
        match workspace_context_from_mount(mount.clone()).await {
            Ok(ctx) => {
                if is_path_mounted(&ctx.mountpoint)? {
                    contexts.push(ctx);
                }
            }
            Err(err) => {
                warn!(
                    path = %mount.display(),
                    "failed to load workspace context: {err}"
                );
            }
        }
    }
    Ok(contexts)
}

async fn publish_workspace_snapshot(
    ctx: &WorkspaceContext,
    publisher: &SnapshotStreamPublisher,
) -> anyhow::Result<()> {
    if !is_path_mounted(&ctx.mountpoint)? {
        return Ok(());
    }
    let snapshot = build_snapshot(&ctx.slug, &ctx.mountpoint)?;
    let bytes = serde_json::to_vec(&snapshot)?;
    let hash = file_hash(&bytes);
    let size_bytes = bytes.len() as u64;
    let req = PublishSnapshotRequest {
        workspace: ctx.slug.clone(),
        node_id: hostname(),
        snapshot_json: bytes,
        size_bytes,
        hash,
    };
    publisher.publish(req).await?;
    Ok(())
}

async fn run_remote_subscription(remote: String, ctx: WorkspaceContext) -> anyhow::Result<()> {
    loop {
        match subscribe_once(&remote, &ctx).await {
            Ok(_) => {
                sleep(Duration::from_secs(1)).await;
            }
            Err(err) => {
                warn!(
                    workspace = %ctx.slug,
                    "remote subscribe error: {err}"
                );
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn subscribe_once(remote: &str, ctx: &WorkspaceContext) -> anyhow::Result<()> {
    let mut client = relay_client(remote).await?;
    let mut last_version = latest_remote_version(&ctx.root)?;
    let request = SubscribeSnapshotsRequest {
        workspace: ctx.slug.clone(),
        from_version: last_version,
    };
    let mut stream = client
        .subscribe_snapshots(Request::new(request))
        .await?
        .into_inner();
    while let Some(envelope) = stream.message().await? {
        if envelope.version <= last_version {
            continue;
        }
        if let Err(err) = apply_remote_snapshot(ctx, &envelope) {
            warn!(
                workspace = %ctx.slug,
                version = envelope.version,
                "failed to apply remote snapshot: {err}"
            );
        } else {
            last_version = envelope.version;
        }
    }
    Ok(())
}

fn apply_remote_snapshot(
    ctx: &WorkspaceContext,
    envelope: &SnapshotEnvelope,
) -> anyhow::Result<()> {
    if !is_path_mounted(&ctx.mountpoint)? {
        return Err(anyhow!("workspace mountpoint is offline"));
    }
    let snapshot: state_sync::WorkspaceSnapshot = serde_json::from_slice(&envelope.snapshot_json)?;
    state_sync::apply_snapshot(&ctx.mountpoint, &snapshot)?;
    persist_local_snapshot(&ctx.root, &snapshot)?;
    archive_remote_snapshot(&ctx.root, envelope.version, &envelope.snapshot_json)?;
    info!(
        workspace = %ctx.slug,
        version = envelope.version,
        bytes = envelope.size_bytes,
        "applied remote snapshot"
    );
    Ok(())
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct WorkspaceConfig {
    workspace_id: String,
    #[serde(default)]
    slug: Option<String>,
    mountpoint: PathBuf,
    lower: PathBuf,
    upper: PathBuf,
    work: PathBuf,
}

async fn run_ls(args: LsArgs) -> anyhow::Result<()> {
    let locals = collect_local_workspace_lines()?;
    println!("Local workspaces:");
    if locals.is_empty() {
        println!("  (none)");
    } else {
        for line in locals {
            println!("  {line}");
        }
    }
    if args.local_only {
        return Ok(());
    }
    println!("\nRelay workspaces (@ {}):", args.remote);
    match list_remote_workspaces(&args.remote).await {
        Ok(remotes) => {
            if remotes.is_empty() {
                println!("  (none)");
            } else {
                for line in remotes {
                    println!("  {line}");
                }
            }
        }
        Err(err) => {
            eprintln!("lit ls: failed to list relay {}: {err}", args.remote);
        }
    }
    Ok(())
}

fn collect_local_workspace_lines() -> anyhow::Result<Vec<String>> {
    let root = lit_home_dir()?.join("workspaces");
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut lines = Vec::new();
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        let entry_path = entry.path();
        if let Some(vm_state) = read_vm_state(&entry_path)? {
            let mounted = is_path_mounted(&vm_state.mountpoint)?;
            let status = if mounted { "ON" } else { "OFF" };
            lines.push(format!(
                "{} [{status}] -> {} (vm {}:{})",
                vm_state.config.workspace,
                vm_state.mountpoint.display(),
                vm_state.config.host,
                vm_state.config.workspace
            ));
            continue;
        }
        let cfg = match read_workspace_config(&entry_path) {
            Ok(cfg) => cfg,
            Err(_) => continue,
        };
        let mounted = is_path_mounted(&cfg.mountpoint)?;
        let status = if mounted { "ON" } else { "OFF" };
        let slug = cfg.slug.clone().unwrap_or_else(|| cfg.workspace_id.clone());
        lines.push(format!(
            "{} [{status}] -> {}",
            slug,
            cfg.mountpoint.display()
        ));
    }
    lines.sort();
    Ok(lines)
}

async fn list_remote_workspaces(remote: &str) -> anyhow::Result<Vec<String>> {
    let mut client = relay_client(remote).await?;
    let resp = client
        .list_workspaces(Request::new(ListWorkspacesRequest {}))
        .await?
        .into_inner();
    let mut lines = Vec::new();
    for ws in resp.workspaces {
        let ts = if ws.updated_at == 0 {
            "-".to_string()
        } else {
            let secs = ws.updated_at as i64;
            match chrono::DateTime::<Utc>::from_timestamp(secs, 0) {
                Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
                None => ws.updated_at.to_string(),
            }
        };
        lines.push(format!(
            "{} v{} (updated {})",
            ws.workspace, ws.latest_version, ts
        ));
    }
    lines.sort();
    Ok(lines)
}

async fn run_sync_once(args: &SyncArgs) -> anyhow::Result<()> {
    let mut client = relay_client(&args.remote).await?;
    let ctx = workspace_context_from_arg(Some(args.workspace.clone())).await?;
    if !is_path_mounted(&ctx.mountpoint)? {
        return Err(anyhow!(
            "workspace {} is not mounted",
            ctx.mountpoint.display()
        ));
    }
    let snapshot = build_snapshot(&ctx.slug, &ctx.mountpoint)?;
    let bytes = serde_json::to_vec(&snapshot)?;
    let hash = file_hash(&bytes);
    let publish_req = PublishSnapshotRequest {
        workspace: ctx.slug.clone(),
        node_id: hostname(),
        snapshot_json: bytes.clone(),
        size_bytes: bytes.len() as u64,
        hash: hash.clone(),
    };
    let publish_resp = client
        .publish_snapshot(Request::new(publish_req))
        .await?
        .into_inner();
    println!(
        "lit sync: published snapshot {} {} ({} bytes)",
        ctx.slug,
        publish_resp.stored_version,
        bytes.len()
    );

    let fetch_resp = client
        .fetch_snapshot(Request::new(FetchSnapshotRequest {
            workspace: ctx.slug.clone(),
        }))
        .await?
        .into_inner();
    let inbox = ctx.root.join("state").join("inbox");
    std::fs::create_dir_all(&inbox)?;
    let inbox_file = inbox.join(format!("remote-{:020}.json", fetch_resp.stored_version));
    std::fs::write(&inbox_file, &fetch_resp.snapshot_json)?;
    println!(
        "lit sync: fetched snapshot {} {} ({} bytes)",
        ctx.slug, fetch_resp.stored_version, fetch_resp.size_bytes
    );
    match apply_incoming_snapshots(&ctx.root, &ctx.mountpoint) {
        Ok(0) => {}
        Ok(applied) => println!("lit sync: applied {applied} incoming snapshot(s)"),
        Err(err) => eprintln!("lit sync: failed to apply incoming snapshots: {err}"),
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

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn run_version() {
    println!("lit {}", env!("CARGO_PKG_VERSION"));
}

async fn run_status(target: Option<PathBuf>) -> anyhow::Result<()> {
    let base = match target {
        Some(path) => path,
        None => std::env::current_dir()?,
    };
    let canonical = fs::canonicalize(&base).await.unwrap_or(base.clone());
    let workspace_id = workspace_id(&canonical).await?;
    let workspace_root = lit_home_dir()?.join("workspaces").join(&workspace_id);
    if let Some(state) = read_vm_state(&workspace_root)? {
        let status = if is_path_mounted(&canonical)? {
            "ON"
        } else {
            "OFF"
        };
        println!("lit status (vm): {}", status);
        println!(" mountpoint: {}", canonical.display());
        println!(" remote host: {}", state.config.host);
        println!(" remote workspace: {}", state.config.workspace);
        return Ok(());
    }
    match workspace_context_from_mount(canonical.clone()).await {
        Ok(ctx) => {
            let state = if is_path_mounted(&ctx.mountpoint)? {
                "ON"
            } else {
                "OFF"
            };
            println!("lit status: {}", state);
            println!(" workspace: {}", ctx.slug);
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
    let workspace_id = workspace_id(&canonical_target).await?;
    let vm_cfg_path = args
        .vm_config
        .or_else(|| env::var("LIT_VM_CONFIG").ok().map(PathBuf::from));
    if let Some(cfg_path) = vm_cfg_path {
        run_on_vm(&canonical_target, &workspace_id, &cfg_path)?;
        return Ok(());
    }

    let slug = match &args.name {
        Some(name) => sanitize_slug(name)?,
        None => default_slug_from_path(&canonical_target)?,
    };

    let lit_home = lit_home_dir()?;
    let workspaces_root = lit_home.join("workspaces");
    fs::create_dir_all(&workspaces_root).await?;

    let workspace_root = workspaces_root.join(&workspace_id);
    let lower = workspace_root.join("lower");
    let upper = workspace_root.join("upper");
    let work = workspace_root.join("work");
    let state_dir = workspace_root.join("state");
    let workspace_exists = workspace_root.exists();
    fs::create_dir_all(&lower).await?;
    fs::create_dir_all(&upper).await?;
    fs::create_dir_all(&work).await?;
    fs::create_dir_all(&state_dir).await?;
    let dirty_flag = state_dir.join("dirty.flag");
    ensure_dirty_flag_file(&dirty_flag);

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
        &slug,
        &lower,
        &upper,
        &work,
    )?;

    let locks_file = workspace_root.join("locks.json");
    spawn_lit_fs_daemon(&upper, &canonical_target, &locks_file, &dirty_flag)?;
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
        slug,
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
    let vm_cfg_path = args
        .vm_config
        .or_else(|| env::var("LIT_VM_CONFIG").ok().map(PathBuf::from));
    if vm_cfg_path.is_some() || vm_state_path(&workspace_root).exists() {
        run_off_vm(&canonical, &workspace_id, vm_cfg_path)?;
        return Ok(());
    }
    if !workspace_root.exists() {
        return Err(anyhow!("{} is not a lit workspace", canonical.display()));
    }
    let upper = workspace_root.join("upper");
    unmount_path(&canonical)?;
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

async fn wait_for_mount(path: &Path) -> anyhow::Result<()> {
    for _ in 0..50 {
        if is_path_mounted(path)? {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(anyhow!(
        "timed out waiting for lit-fs to mount {}",
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

fn sanitize_slug(input: &str) -> anyhow::Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("workspace name must not be empty"));
    }
    let mut slug = String::new();
    for ch in trimmed.chars() {
        match ch {
            'a'..='z' | '0'..='9' | '-' | '_' => slug.push(ch),
            'A'..='Z' => slug.push(ch.to_ascii_lowercase()),
            ' ' | '.' | '/' | '\\' => slug.push('-'),
            _ => {
                return Err(anyhow!(
                    "workspace name may only contain [a-z0-9-_]; got '{ch}'"
                ))
            }
        }
    }
    if slug.is_empty() {
        return Err(anyhow!("workspace name became empty after sanitization"));
    }
    Ok(slug)
}

fn default_slug_from_path(path: &Path) -> anyhow::Result<String> {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        sanitize_slug(name)
    } else {
        Err(anyhow!(
            "cannot derive workspace name from {}",
            path.display()
        ))
    }
}

fn lit_home_dir() -> anyhow::Result<PathBuf> {
    let home = home_dir().ok_or_else(|| anyhow!("cannot determine home directory"))?;
    let lit_home = home.join(".lit");
    std::fs::create_dir_all(&lit_home)?;
    Ok(lit_home)
}

#[derive(Clone)]
struct WorkspaceContext {
    mountpoint: PathBuf,
    root: PathBuf,
    lower: PathBuf,
    upper: PathBuf,
    slug: String,
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
        let slug =
            workspace_slug_from_root(&root, &mountpoint).unwrap_or_else(|_| workspace_id.clone());
        Ok(WorkspaceContext {
            mountpoint,
            root,
            lower,
            upper,
            slug,
        })
    }
}

fn dirty_flag_path(root: &Path) -> PathBuf {
    root.join("state").join("dirty.flag")
}

fn ensure_dirty_flag_file(path: &Path) {
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, b"0\n");
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
    slug: &str,
    lower: &Path,
    upper: &Path,
    work: &Path,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(root)?;
    let config_path = root.join("workspace.json");
    let payload = json!({
        "workspace_id": workspace_id,
        "slug": slug,
        "mountpoint": mountpoint,
        "lower": lower,
        "upper": upper,
        "work": work
    });
    let mut file = File::create(config_path)?;
    file.write_all(serde_json::to_string_pretty(&payload)?.as_bytes())?;
    Ok(())
}

fn workspace_config_path(root: &Path) -> PathBuf {
    root.join("workspace.json")
}

fn read_workspace_config(root: &Path) -> anyhow::Result<WorkspaceConfig> {
    let path = workspace_config_path(root);
    let bytes = std::fs::read(&path)?;
    let cfg = serde_json::from_slice::<WorkspaceConfig>(&bytes)?;
    Ok(cfg)
}

fn workspace_slug_from_root(root: &Path, mountpoint: &Path) -> anyhow::Result<String> {
    match read_workspace_config(root) {
        Ok(cfg) => {
            if let Some(slug) = cfg.slug {
                Ok(slug)
            } else {
                default_slug_from_path(mountpoint)
            }
        }
        Err(err) => {
            if err
                .downcast_ref::<std::io::Error>()
                .map(|e| e.kind() == std::io::ErrorKind::NotFound)
                .unwrap_or(false)
            {
                default_slug_from_path(mountpoint)
            } else {
                Err(err)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn is_path_mounted(path: &Path) -> anyhow::Result<bool> {
    const FUSE_SUPER_MAGIC: libc::c_long = 0x65735546;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let res = unsafe { libc::statfs(c_path.as_ptr(), &mut stat) };
    if res != 0 {
        return Err(anyhow!(
            "statfs failed for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(stat.f_type == FUSE_SUPER_MAGIC)
}

#[cfg(target_os = "macos")]
fn is_path_mounted(path: &Path) -> anyhow::Result<bool> {
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let res = unsafe { libc::statfs(c_path.as_ptr(), &mut stat) };
    if res != 0 {
        return Err(anyhow!(
            "statfs failed for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let fs_name = unsafe { CStr::from_ptr(stat.f_fstypename.as_ptr()) };
    Ok(fs_name.to_string_lossy().to_lowercase().contains("fuse"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn is_path_mounted(path: &Path) -> anyhow::Result<bool> {
    match Command::new("mountpoint").arg("-q").arg(path).status() {
        Ok(status) => Ok(status.success()),
        Err(err) => Err(anyhow!("failed to check mount status: {err}")),
    }
}

fn spawn_lit_fs_daemon(
    source: &Path,
    mountpoint: &Path,
    locks_file: &Path,
    dirty_flag: &Path,
) -> anyhow::Result<()> {
    let bin = which::which("lit-fs").context("lit-fs binary not found")?;
    std::fs::create_dir_all(source)?;
    Command::new(bin)
        .arg("--source")
        .arg(source)
        .arg("--mountpoint")
        .arg(mountpoint)
        .arg("--locks-file")
        .arg(locks_file)
        .arg("--dirty-flag")
        .arg(dirty_flag)
        .spawn()
        .map(|_| ())
        .map_err(|e| anyhow!("failed to spawn lit-fs: {e}"))
}

fn unmount_path(target: &Path) -> anyhow::Result<()> {
    let mut last_error = None;
    let commands = vec![
        ("fusermount3", vec!["-u"]),
        ("fusermount", vec!["-u"]),
        ("umount", Vec::<&str>::new()),
        ("diskutil", vec!["umount"]),
    ];
    for (cmd, args) in commands {
        match which::which(cmd) {
            Ok(path) => {
                let status = Command::new(path).args(&args).arg(target).status();
                match status {
                    Ok(status) if status.success() => return Ok(()),
                    Ok(status) => {
                        last_error = Some(anyhow!("{} exited with status {}", cmd, status))
                    }
                    Err(err) => last_error = Some(anyhow!("failed to run {}: {err}", cmd)),
                }
            }
            Err(_) => continue,
        }
    }
    Err(last_error.unwrap_or_else(|| {
        anyhow!(
            "no supported unmount command found for {}",
            target.display()
        )
    }))
}

#[derive(Serialize, Deserialize, Default)]
struct WatchState {
    paths: Vec<String>,
}

struct WatchLists {
    global: HashSet<String>,
    session: HashSet<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct VmConfig {
    host: String,
    workspace: String,
    #[serde(default = "default_vm_lit_root")]
    lit_root: String,
    #[serde(default = "default_vm_export_file")]
    export_file: String,
    #[serde(default = "default_vm_mount_options")]
    mount_options: String,
    #[serde(default = "default_vm_install_nfs")]
    install_nfs: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct VmWorkspaceState {
    config: VmConfig,
    mountpoint: PathBuf,
}

fn default_vm_lit_root() -> String {
    "~/lit".to_string()
}

fn default_vm_export_file() -> String {
    "/etc/exports.d/lit-vm.exports".to_string()
}

fn default_vm_mount_options() -> String {
    "vers=4".to_string()
}

fn default_vm_install_nfs() -> bool {
    true
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

fn load_vm_config(path: &Path) -> anyhow::Result<VmConfig> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read vm config {}", path.display()))?;
    let config: VmConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid vm config {}", path.display()))?;
    Ok(config)
}

fn vm_state_path(root: &Path) -> PathBuf {
    root.join("vm.json")
}

fn save_vm_state(root: &Path, state: &VmWorkspaceState) -> anyhow::Result<()> {
    std::fs::create_dir_all(root)?;
    let path = vm_state_path(root);
    std::fs::write(&path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}

fn read_vm_state(root: &Path) -> anyhow::Result<Option<VmWorkspaceState>> {
    let path = vm_state_path(root);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)?;
    let state = serde_json::from_slice(&bytes)?;
    Ok(Some(state))
}

fn shell_quote(input: &str) -> String {
    let mut quoted = String::from("'");
    for ch in input.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn run_remote(host: &str, command: &str) -> anyhow::Result<()> {
    let status = Command::new("ssh")
        .arg(host)
        .arg(command)
        .status()
        .with_context(|| format!("failed to run ssh {host}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("ssh {host} exited with status {status}"))
    }
}

fn run_remote_bash(host: &str, script: &str) -> anyhow::Result<()> {
    let wrapped = format!("bash -lc {}", shell_quote(script));
    run_remote(host, &wrapped)
}

fn run_remote_capture(host: &str, command: &str) -> anyhow::Result<String> {
    let output = Command::new("ssh")
        .arg(host)
        .arg(command)
        .output()
        .with_context(|| format!("failed to run ssh {host}"))?;
    if !output.status.success() {
        return Err(anyhow!("ssh {host} exited with status {}", output.status));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn prepare_vm_workspace(cfg: &VmConfig) -> anyhow::Result<()> {
    if cfg.install_nfs {
        run_remote(
            &cfg.host,
            "sudo apt-get update -qq && sudo apt-get install -y nfs-kernel-server",
        )?;
    }
    run_remote(
        &cfg.host,
        &format!("mkdir -p {}", shell_quote(&cfg.workspace)),
    )?;
    let lit_cmd = format!(
        "cd {} && . $HOME/.cargo/env && (lit info {} >/dev/null 2>&1 && lit off {} || true) && lit on {}",
        shell_quote(&cfg.lit_root),
        shell_quote(&cfg.workspace),
        shell_quote(&cfg.workspace),
        shell_quote(&cfg.workspace)
    );
    run_remote_bash(&cfg.host, &lit_cmd)?;
    configure_vm_export(cfg)?;
    Ok(())
}

fn file_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn configure_vm_export(cfg: &VmConfig) -> anyhow::Result<()> {
    let uid = run_remote_capture(&cfg.host, "id -u")?;
    let gid = run_remote_capture(&cfg.host, "id -g")?;
    let export_path = Path::new(&cfg.export_file);
    let dir = export_path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/etc".to_string());
    run_remote(&cfg.host, &format!("sudo mkdir -p {}", shell_quote(&dir)))?;
    let line = format!(
        "{} *(rw,sync,no_subtree_check,all_squash,anonuid={},anongid={})",
        &cfg.workspace, uid, gid
    );
    let cmd = format!(
        "printf %s\\n {} | sudo tee {} > /dev/null",
        shell_quote(&line),
        shell_quote(&cfg.export_file)
    );
    run_remote(&cfg.host, &cmd)?;
    run_remote(&cfg.host, "sudo exportfs -ra")?;
    Ok(())
}

fn stop_vm_workspace(cfg: &VmConfig) -> anyhow::Result<()> {
    let lit_cmd = format!(
        "cd {} && . $HOME/.cargo/env && (lit info {} >/dev/null 2>&1 && lit off {} || true)",
        shell_quote(&cfg.lit_root),
        shell_quote(&cfg.workspace),
        shell_quote(&cfg.workspace)
    );
    run_remote_bash(&cfg.host, &lit_cmd)
}

fn clear_vm_export(cfg: &VmConfig) -> anyhow::Result<()> {
    let cmd = format!(
        "sudo rm -f {} && sudo exportfs -ra",
        shell_quote(&cfg.export_file)
    );
    run_remote(&cfg.host, &cmd)
}

fn mount_vm_workspace(cfg: &VmConfig, target: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(target)?;
    let status = Command::new("sudo")
        .arg("mount")
        .arg("-t")
        .arg("nfs")
        .arg("-o")
        .arg(&cfg.mount_options)
        .arg(format!("{}:{}", cfg.host, cfg.workspace))
        .arg(target)
        .status()
        .context("failed to run sudo mount")?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("mount failed with status {status}"))
    }
}

fn run_on_vm(canonical_target: &Path, workspace_id: &str, cfg_path: &Path) -> anyhow::Result<()> {
    let cfg = load_vm_config(cfg_path)?;
    let workspace_root = lit_home_dir()?.join("workspaces").join(workspace_id);
    prepare_vm_workspace(&cfg)?;
    if let Err(err) = mount_vm_workspace(&cfg, canonical_target) {
        let _ = stop_vm_workspace(&cfg);
        return Err(err);
    }
    save_vm_state(
        &workspace_root,
        &VmWorkspaceState {
            config: cfg.clone(),
            mountpoint: canonical_target.to_path_buf(),
        },
    )?;
    println!(
        "lit(vm): mounted {} from {}:{}",
        canonical_target.display(),
        cfg.host,
        cfg.workspace
    );
    Ok(())
}

fn run_off_vm(
    canonical_target: &Path,
    workspace_id: &str,
    override_cfg: Option<PathBuf>,
) -> anyhow::Result<()> {
    let workspace_root = lit_home_dir()?.join("workspaces").join(workspace_id);
    let state = if let Some(path) = override_cfg {
        VmWorkspaceState {
            config: load_vm_config(&path)?,
            mountpoint: canonical_target.to_path_buf(),
        }
    } else {
        read_vm_state(&workspace_root)?.ok_or_else(|| {
            anyhow!(
                "{} is not a vm-backed lit workspace",
                canonical_target.display()
            )
        })?
    };
    if is_path_mounted(canonical_target)? {
        unmount_path(canonical_target)?;
    }
    stop_vm_workspace(&state.config)?;
    clear_vm_export(&state.config)?;
    let state_path = vm_state_path(&workspace_root);
    if state_path.exists() {
        std::fs::remove_file(state_path)?;
    }
    if workspace_root.exists() {
        let _ = std::fs::remove_dir_all(&workspace_root);
    }
    println!("lit(vm): unmounted {}", canonical_target.display());
    Ok(())
}

fn daemon_state_path() -> anyhow::Result<PathBuf> {
    Ok(lit_home_dir()?.join("daemon.json"))
}

fn load_daemon_state() -> anyhow::Result<DaemonState> {
    let path = daemon_state_path()?;
    if !path.exists() {
        return Ok(DaemonState::default());
    }
    let bytes = std::fs::read(&path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn save_daemon_state(state: &DaemonState) -> anyhow::Result<()> {
    let path = daemon_state_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}

fn process_alive(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{pid}")).exists()
}

fn terminate_process(pid: u32) -> anyhow::Result<()> {
    unsafe {
        if libc::kill(pid as i32, libc::SIGTERM) != 0 {
            return Err(anyhow!("failed to terminate pid {}", pid));
        }
    }
    Ok(())
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

#[derive(Serialize, Deserialize, Default)]
struct DaemonState {
    relay_pid: Option<u32>,
    relay_addr: Option<String>,
    relay_storage: Option<PathBuf>,
    sync_pid: Option<u32>,
    sync_remote: Option<String>,
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
