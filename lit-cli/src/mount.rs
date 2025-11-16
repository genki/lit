use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const STATE_FILE: &str = "mount.json";

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct MountState {
    pub lower: PathBuf,
    pub mountpoint: PathBuf,
}

pub fn write_state(root: &Path, state: &MountState) -> Result<()> {
    let path = root.join(STATE_FILE);
    fs::create_dir_all(root)?;
    fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}

pub fn read_state(root: &Path) -> Result<MountState> {
    let path = root.join(STATE_FILE);
    if !path.exists() {
        return Err(anyhow!("mount state not found at {}", path.display()));
    }
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn clear_state(root: &Path) -> Result<()> {
    let path = root.join(STATE_FILE);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}
