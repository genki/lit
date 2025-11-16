use crate::{StorageBackend, StorageConfig, StorageError, StorageResult};
use async_trait::async_trait;
use std::path::PathBuf;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone)]
pub struct FsBackend {
    root: PathBuf,
}

impl FsBackend {
    pub fn new(config: StorageConfig) -> Self {
        Self { root: config.root }
    }

    fn resolve(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }
}

#[async_trait]
impl StorageBackend for FsBackend {
    async fn put_object(&self, key: &str, bytes: &[u8]) -> StorageResult<()> {
        let path = self.resolve(key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let mut file = File::create(&path).await?;
        file.write_all(bytes).await?;
        file.flush().await?;
        Ok(())
    }

    async fn get_object(&self, key: &str) -> StorageResult<Vec<u8>> {
        let path = self.resolve(key);
        match fs::read(&path).await {
            Ok(bytes) => Ok(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(key.to_string()))
            }
            Err(err) => Err(err.into()),
        }
    }

    async fn delete_object(&self, key: &str) -> StorageResult<()> {
        let path = self.resolve(key);
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    async fn list_objects(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let mut entries = Vec::new();
        let search_root = if prefix.is_empty() {
            self.root.clone()
        } else {
            self.resolve(prefix)
        };
        if !search_root.exists() {
            return Ok(entries);
        }
        let mut stack = vec![search_root];
        while let Some(path) = stack.pop() {
            let mut dir = fs::read_dir(&path).await?;
            while let Some(entry) = dir.next_entry().await? {
                let metadata = entry.metadata().await?;
                if metadata.is_dir() {
                    stack.push(entry.path());
                } else if metadata.is_file() {
                    let rel = entry
                        .path()
                        .strip_prefix(&self.root)
                        .unwrap_or(entry.path().as_path())
                        .to_string_lossy()
                        .to_string();
                    if prefix.is_empty() || rel.starts_with(prefix) {
                        entries.push(rel);
                    }
                }
            }
        }
        entries.sort();
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StorageError;
    use tempfile::tempdir;

    #[tokio::test]
    async fn roundtrip_put_get_delete() {
        let tmp = tempdir().unwrap();
        let backend = FsBackend::new(StorageConfig::new(tmp.path()));
        backend.put_object("logs/seg1", b"hello").await.unwrap();
        let bytes = backend.get_object("logs/seg1").await.unwrap();
        assert_eq!(bytes, b"hello");
        backend.delete_object("logs/seg1").await.unwrap();
        let err = backend.get_object("logs/seg1").await.unwrap_err();
        matches!(err, StorageError::NotFound(_));
    }
}
