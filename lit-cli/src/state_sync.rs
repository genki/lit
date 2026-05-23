use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileState {
    pub path: String,
    pub hash: String,
    pub size: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkspaceSnapshot {
    pub workspace: String,
    pub files: Vec<FileState>,
}

pub fn build_snapshot(workspace: &str, mountpoint: &Path) -> anyhow::Result<WorkspaceSnapshot> {
    if !mountpoint.is_dir() {
        return Err(anyhow!("{} is not a directory", mountpoint.display()));
    }
    let mut entries = Vec::new();
    collect(mountpoint, mountpoint, &mut entries)?;
    Ok(WorkspaceSnapshot {
        workspace: workspace.to_string(),
        files: entries,
    })
}

#[allow(dead_code)]
pub fn write_snapshot(path: &Path, snapshot: &WorkspaceSnapshot) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_vec_pretty(snapshot)?;
    fs::write(path, json)?;
    Ok(())
}

fn collect(base: &Path, current: &Path, entries: &mut Vec<FileState>) -> anyhow::Result<()> {
    if current.is_file() {
        let rel = relative_path(base, current);
        let data = fs::read(current)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = format!("{:x}", hasher.finalize());
        let size = data.len() as u64;
        entries.push(FileState {
            path: rel,
            hash,
            size,
            data,
        });
        return Ok(());
    }
    if !current.is_dir() {
        return Ok(());
    }
    if let Some(name) = current.file_name() {
        if name == ".lit" {
            return Ok(());
        }
    }
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        collect(base, &entry.path(), entries)?;
    }
    Ok(())
}

fn relative_path(base: &Path, target: &Path) -> String {
    let mut components = Vec::new();
    let rel = target.strip_prefix(base).unwrap_or(target);
    for comp in rel.components() {
        match comp {
            Component::Normal(part) => components.push(part.to_string_lossy().replace('\\', "/")),
            Component::CurDir => (),
            _ => (),
        }
    }
    if components.is_empty() {
        target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string())
    } else {
        components.join("/")
    }
}

pub fn apply_snapshot(destination: &Path, snapshot: &WorkspaceSnapshot) -> anyhow::Result<()> {
    if !destination.exists() {
        fs::create_dir_all(destination)?;
    }
    for file in &snapshot.files {
        let path = destination.join(&file.path);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&path, &file.data).with_context(|| format!("failed to write {:?}", path))?;
    }
    Ok(())
}

pub fn read_snapshot(path: &Path) -> anyhow::Result<WorkspaceSnapshot> {
    let bytes = fs::read(path)?;
    let snapshot: WorkspaceSnapshot = serde_json::from_slice(&bytes)?;
    Ok(snapshot)
}

#[allow(dead_code)]
pub fn snapshot_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join("state").join("latest.json")
}

#[allow(dead_code)]
pub fn persist_local_snapshot(
    workspace_root: &Path,
    snapshot: &WorkspaceSnapshot,
) -> anyhow::Result<PathBuf> {
    let path = snapshot_path(workspace_root);
    write_snapshot(&path, snapshot)?;
    Ok(path)
}

#[allow(dead_code)]
pub fn estimate_snapshot_size(snapshot: &WorkspaceSnapshot) -> u64 {
    snapshot.files.iter().map(|f| f.size).sum()
}

#[allow(dead_code)]
pub fn copy_snapshot_to<W: Write>(
    snapshot: &WorkspaceSnapshot,
    mut writer: W,
) -> anyhow::Result<()> {
    let json = serde_json::to_vec(snapshot)?;
    writer.write_all(&json)?;
    Ok(())
}

fn inbox_dir(workspace_root: &Path) -> PathBuf {
    workspace_root.join("state").join("inbox")
}

fn applied_dir(workspace_root: &Path) -> PathBuf {
    workspace_root.join("state").join("applied")
}

pub fn list_incoming_snapshots(workspace_root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let dir = inbox_dir(workspace_root);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut files: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().map(|ext| ext == "json").unwrap_or(false))
        .collect();
    files.sort();
    Ok(files)
}

pub fn apply_incoming_snapshots(workspace_root: &Path, mountpoint: &Path) -> anyhow::Result<usize> {
    let files = list_incoming_snapshots(workspace_root)?;
    if files.is_empty() {
        return Ok(0);
    }
    let archive = applied_dir(workspace_root);
    fs::create_dir_all(&archive)?;
    let mut count = 0;
    for file in files {
        let snapshot = read_snapshot(&file)
            .with_context(|| format!("failed to read snapshot {}", file.display()))?;
        apply_snapshot(mountpoint, &snapshot)
            .with_context(|| format!("failed to apply snapshot {}", file.display()))?;
        let name = file
            .file_name()
            .map(|n| n.to_owned())
            .unwrap_or_else(|| std::ffi::OsString::from("applied.json"));
        let dest = archive.join(name);
        if let Err(_) = fs::rename(&file, &dest) {
            fs::copy(&file, &dest)?;
            fs::remove_file(&file)?;
        }
        count += 1;
    }
    Ok(count)
}

pub fn latest_remote_version(workspace_root: &Path) -> anyhow::Result<u64> {
    let dir = applied_dir(workspace_root);
    if !dir.exists() {
        return Ok(0);
    }
    let mut max_version = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.path().is_file() {
            continue;
        }
        if let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
            if let Some(rest) = stem.strip_prefix("remote-") {
                if let Ok(value) = rest.parse::<u64>() {
                    if value > max_version {
                        max_version = value;
                    }
                }
            }
        }
    }
    Ok(max_version)
}

pub fn archive_remote_snapshot(
    workspace_root: &Path,
    version: u64,
    bytes: &[u8],
) -> anyhow::Result<PathBuf> {
    let dir = applied_dir(workspace_root);
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("remote-{version:020}.json"));
    fs::write(&path, bytes)?;
    Ok(path)
}
