use anyhow::{anyhow, Context, Result};
use clap::Parser;
use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, MountOption, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use libc::{EACCES, ENOENT, ENOSYS};
use serde::Deserialize;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    source: PathBuf,
    #[arg(long)]
    mountpoint: PathBuf,
    #[arg(long)]
    locks_file: Option<PathBuf>,
}

#[derive(Default)]
struct InodeMap {
    next: u64,
    ino_to_path: HashMap<u64, PathBuf>,
    path_to_ino: HashMap<PathBuf, u64>,
}

impl InodeMap {
    fn new(root: PathBuf) -> Self {
        let mut map = InodeMap {
            next: ROOT_INO + 1,
            ino_to_path: HashMap::new(),
            path_to_ino: HashMap::new(),
        };
        map.ino_to_path.insert(ROOT_INO, root.clone());
        map.path_to_ino.insert(root, ROOT_INO);
        map
    }

    fn get_or_insert(&mut self, path: &Path) -> u64 {
        if let Some(ino) = self.path_to_ino.get(path) {
            *ino
        } else {
            let ino = self.next;
            self.next += 1;
            self.path_to_ino.insert(path.to_path_buf(), ino);
            self.ino_to_path.insert(ino, path.to_path_buf());
            ino
        }
    }

    fn get_path(&self, ino: u64) -> Option<PathBuf> {
        self.ino_to_path.get(&ino).cloned()
    }
}

struct LitFilesystem {
    inode_map: Mutex<InodeMap>,
    root: PathBuf,
    lock_manager: Option<LockManager>,
}

struct LockManager {
    file: PathBuf,
}

#[derive(Clone, Deserialize)]
struct LockEntryFs {
    path: String,
    owner_uid: u32,
    owner_pid: u32,
    message: Option<String>,
    expires_at: Option<i64>,
    #[serde(default)]
    owner_session: Option<String>,
}

#[derive(Deserialize, Default)]
struct LocksStateFs {
    locks: Vec<LockEntryFs>,
}

struct LockError {
    message: String,
}

impl LitFilesystem {
    fn new(root: PathBuf, locks_file: Option<PathBuf>) -> Self {
        let inode_map = Mutex::new(InodeMap::new(root.clone()));
        let lock_manager = locks_file.map(LockManager::new);
        Self {
            inode_map,
            root,
            lock_manager,
        }
    }

    fn path_from_parent(&self, parent: u64, name: &OsStr) -> Result<PathBuf> {
        let map = self.inode_map.lock().unwrap();
        let parent_path = map
            .get_path(parent)
            .ok_or_else(|| anyhow!("unknown parent inode {parent}"))?;
        Ok(parent_path.join(name))
    }

    fn file_attr(ino: u64, meta: std::fs::Metadata) -> FileAttr {
        FileAttr {
            ino,
            size: meta.len(),
            blocks: meta.blocks(),
            atime: SystemTime::UNIX_EPOCH + Duration::from_secs(meta.atime() as u64),
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(meta.mtime() as u64),
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(meta.ctime() as u64),
            crtime: SystemTime::UNIX_EPOCH,
            kind: if meta.is_dir() {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: meta.mode() as u16,
            nlink: meta.nlink() as u32,
            uid: meta.uid(),
            gid: meta.gid(),
            rdev: meta.rdev() as u32,
            blksize: meta.blksize() as u32,
            flags: 0,
        }
    }

    fn path_relative_str(&self, path: &Path) -> Option<String> {
        path.strip_prefix(&self.root)
            .ok()
            .map(|rel| normalize_relative_path(rel))
    }

    fn ensure_can_mutate(&self, req: &Request, path: &Path, op: &str) -> Result<(), libc::c_int> {
        if let Some(manager) = &self.lock_manager {
            if let Some(rel) = self.path_relative_str(path) {
                if let Err(err) = manager.check(&rel, req.uid(), req.pid()) {
                    warn!(
                        operation = op,
                        path = %rel,
                        uid = req.uid(),
                        pid = req.pid(),
                        "blocked by lock: {}",
                        err.message
                    );
                    eprintln!(
                        "lit-fs: {} on {} denied (uid={} pid={}) -> {}",
                        op,
                        rel,
                        req.uid(),
                        req.pid(),
                        err.message
                    );
                    return Err(EACCES);
                }
            }
        }
        Ok(())
    }
}

impl LockManager {
    fn new(file: PathBuf) -> Self {
        Self { file }
    }

    fn check(&self, rel: &str, uid: u32, pid: u32) -> Result<(), LockError> {
        let state = match self.load_state() {
            Ok(state) => state,
            Err(err) => {
                warn!("failed to load locks: {err}");
                return Ok(());
            }
        };
        let now = unix_timestamp();
        for entry in state.locks.into_iter() {
            if entry.path != rel {
                continue;
            }
            if entry.expires_at.map(|exp| now > exp).unwrap_or(false) {
                continue;
            }
            if entry.owner_uid == uid && entry.owner_pid == pid {
                return Ok(());
            }
            let message = entry
                .message
                .clone()
                .unwrap_or_else(|| "locked by another process".to_string());
            return Err(LockError { message });
        }
        Ok(())
    }

    fn load_state(&self) -> anyhow::Result<LocksStateFs> {
        match fs::read(&self.file) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(LocksStateFs::default()),
            Err(err) => Err(err.into()),
        }
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn normalize_relative_path(path: &Path) -> String {
    let mut segments = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if segments.is_empty() {
                    segments.push("..".to_string());
                } else {
                    segments.pop();
                }
            }
            std::path::Component::Normal(part) => {
                segments.push(part.to_string_lossy().replace('\\', "/"));
            }
            std::path::Component::RootDir => {}
            std::path::Component::Prefix(prefix) => {
                segments.push(prefix.as_os_str().to_string_lossy().replace('\\', "/"));
            }
        }
    }
    if segments.is_empty() {
        ".".to_string()
    } else {
        segments.join("/")
    }
}

impl Filesystem for LitFilesystem {
    fn init(&mut self, req: &Request, _cfg: &mut KernelConfig) -> Result<(), libc::c_int> {
        info!("lit-fs init pid={} uid={}", req.pid(), req.uid());
        Ok(())
    }

    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self.path_from_parent(parent, name) {
            Ok(path) => match fs::metadata(&path) {
                Ok(meta) => {
                    let mut map = self.inode_map.lock().unwrap();
                    let ino = map.get_or_insert(&path);
                    let attr = Self::file_attr(ino, meta);
                    reply.entry(&TTL, &attr, 0);
                }
                Err(_) => reply.error(ENOENT),
            },
            Err(_) => reply.error(ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        let path_opt = { self.inode_map.lock().unwrap().get_path(ino) };
        match path_opt {
            Some(path) => match fs::metadata(&path) {
                Ok(meta) => reply.attr(&TTL, &Self::file_attr(ino, meta)),
                Err(_) => reply.error(ENOENT),
            },
            None => reply.error(ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path_opt = { self.inode_map.lock().unwrap().get_path(ino) };
        let path = match path_opt {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let mut entries = vec![
            (ino, FileType::Directory, ".".to_string()),
            (ROOT_INO, FileType::Directory, "..".to_string()),
        ];
        if let Ok(read_dir) = fs::read_dir(&path) {
            for entry in read_dir.flatten() {
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let child_path = entry.path();
                let mut map = self.inode_map.lock().unwrap();
                let child_ino = map.get_or_insert(&child_path);
                let kind = if meta.is_dir() {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                if let Some(name) = entry.file_name().to_str() {
                    entries.push((child_ino, kind, name.to_string()));
                }
            }
        }
        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(ino, (i + 1) as i64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(ino, 0);
    }

    fn read(
        &mut self,
        req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let path_opt = { self.inode_map.lock().unwrap().get_path(ino) };
        let path = match path_opt {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        info!("read pid={} path={}", req.pid(), path.display());
        match File::open(&path) {
            Ok(mut file) => {
                if let Err(_) = file.seek(SeekFrom::Start(offset as u64)) {
                    reply.error(ENOSYS);
                    return;
                }
                let mut buf = vec![0; size as usize];
                match file.read(&mut buf) {
                    Ok(bytes) => reply.data(&buf[..bytes]),
                    Err(_) => reply.error(ENOSYS),
                }
            }
            Err(_) => reply.error(ENOENT),
        }
    }

    fn write(
        &mut self,
        req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let path_opt = { self.inode_map.lock().unwrap().get_path(ino) };
        let path = match path_opt {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        if let Err(code) = self.ensure_can_mutate(req, &path, "write") {
            reply.error(code);
            return;
        }
        info!(
            "write pid={} bytes={} path={}",
            req.pid(),
            data.len(),
            path.display()
        );
        let mut file = match OpenOptions::new().write(true).open(&path) {
            Ok(f) => f,
            Err(_) => {
                reply.error(ENOENT);
                return;
            }
        };
        if let Err(_) = file.seek(SeekFrom::Start(offset as u64)) {
            reply.error(ENOSYS);
            return;
        }
        match file.write(data) {
            Ok(written) => reply.written(written as u32),
            Err(_) => reply.error(ENOSYS),
        }
    }

    fn mkdir(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        match self.path_from_parent(parent, name) {
            Ok(path) => {
                if let Err(code) = self.ensure_can_mutate(req, &path, "mkdir") {
                    reply.error(code);
                    return;
                }
                match fs::create_dir(&path) {
                    Ok(_) => {
                        let meta = fs::metadata(&path).unwrap();
                        let mut map = self.inode_map.lock().unwrap();
                        let ino = map.get_or_insert(&path);
                        reply.entry(&TTL, &Self::file_attr(ino, meta), 0);
                    }
                    Err(err) => reply.error(err.raw_os_error().unwrap_or(ENOSYS)),
                }
            }
            Err(_) => reply.error(ENOSYS),
        }
    }

    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        match self.path_from_parent(parent, name) {
            Ok(path) => {
                if let Err(code) = self.ensure_can_mutate(req, &path, "create") {
                    reply.error(code);
                    return;
                }
                match File::create(&path) {
                    Ok(_) => {
                        let meta = fs::metadata(&path).unwrap();
                        let mut map = self.inode_map.lock().unwrap();
                        let ino = map.get_or_insert(&path);
                        reply.created(&TTL, &Self::file_attr(ino, meta), 0, ino, 0);
                    }
                    Err(err) => reply.error(err.raw_os_error().unwrap_or(ENOSYS)),
                }
            }
            Err(_) => reply.error(ENOSYS),
        }
    }

    fn unlink(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.path_from_parent(parent, name) {
            Ok(path) => {
                if let Err(code) = self.ensure_can_mutate(req, &path, "unlink") {
                    reply.error(code);
                    return;
                }
                match fs::remove_file(&path) {
                    Ok(_) => reply.ok(),
                    Err(err) => reply.error(err.raw_os_error().unwrap_or(ENOSYS)),
                }
            }
            Err(_) => reply.error(ENOSYS),
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();
    let args = Args::parse();
    if !args.source.exists() {
        return Err(anyhow!("source directory {:?} does not exist", args.source));
    }
    info!(
        source = %args.source.display(),
        mount = %args.mountpoint.display(),
        "starting lit-fs"
    );
    let source = args.source.canonicalize()?;
    let fs = LitFilesystem::new(source, args.locks_file.clone());
    let options = vec![MountOption::FSName("lit".into()), MountOption::RW];
    fuser::mount2(fs, &args.mountpoint, &options).context("mount failed")?;
    Ok(())
}
