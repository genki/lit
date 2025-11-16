use anyhow::{anyhow, Context, Result};
use clap::Parser;
use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, MountOption, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use libc::{ENOENT, ENOSYS};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tracing::info;

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    source: PathBuf,
    #[arg(long)]
    mountpoint: PathBuf,
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
}

impl LitFilesystem {
    fn new(root: PathBuf) -> Self {
        let inode_map = Mutex::new(InodeMap::new(root));
        Self { inode_map }
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
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        match self.path_from_parent(parent, name) {
            Ok(path) => match fs::create_dir(&path) {
                Ok(_) => {
                    let meta = fs::metadata(&path).unwrap();
                    let mut map = self.inode_map.lock().unwrap();
                    let ino = map.get_or_insert(&path);
                    reply.entry(&TTL, &Self::file_attr(ino, meta), 0);
                }
                Err(err) => reply.error(err.raw_os_error().unwrap_or(ENOSYS)),
            },
            Err(_) => reply.error(ENOSYS),
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        match self.path_from_parent(parent, name) {
            Ok(path) => match File::create(&path) {
                Ok(_) => {
                    let meta = fs::metadata(&path).unwrap();
                    let mut map = self.inode_map.lock().unwrap();
                    let ino = map.get_or_insert(&path);
                    reply.created(&TTL, &Self::file_attr(ino, meta), 0, ino, 0);
                }
                Err(err) => reply.error(err.raw_os_error().unwrap_or(ENOSYS)),
            },
            Err(_) => reply.error(ENOSYS),
        }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.path_from_parent(parent, name) {
            Ok(path) => match fs::remove_file(&path) {
                Ok(_) => reply.ok(),
                Err(err) => reply.error(err.raw_os_error().unwrap_or(ENOSYS)),
            },
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
    let fs = LitFilesystem::new(args.source.canonicalize()?);
    let options = vec![MountOption::FSName("lit".into()), MountOption::RW];
    fuser::mount2(fs, &args.mountpoint, &options).context("mount failed")?;
    Ok(())
}
