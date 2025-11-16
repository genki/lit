mod fs;
mod mem;

use async_trait::async_trait;
use std::path::PathBuf;

pub use crate::fs::FsBackend;
pub use crate::mem::MemBackend;

pub type StorageResult<T> = Result<T, StorageError>;

#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error("object not found: {0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[async_trait]
pub trait StorageBackend: Send + Sync + 'static {
    async fn put_object(&self, key: &str, bytes: &[u8]) -> StorageResult<()>;
    async fn get_object(&self, key: &str) -> StorageResult<Vec<u8>>;
    async fn delete_object(&self, key: &str) -> StorageResult<()>;
    async fn list_objects(&self, prefix: &str) -> StorageResult<Vec<String>>;
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub root: PathBuf,
}

impl StorageConfig {
    pub fn new<P: Into<PathBuf>>(root: P) -> Self {
        Self { root: root.into() }
    }
}
