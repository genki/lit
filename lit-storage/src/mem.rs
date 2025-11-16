use crate::{StorageBackend, StorageError, StorageResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct MemBackend {
    inner: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

#[async_trait]
impl StorageBackend for MemBackend {
    async fn put_object(&self, key: &str, bytes: &[u8]) -> StorageResult<()> {
        let mut guard = self.inner.write().await;
        guard.insert(key.to_string(), bytes.to_vec());
        Ok(())
    }

    async fn get_object(&self, key: &str) -> StorageResult<Vec<u8>> {
        let guard = self.inner.read().await;
        guard
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.to_string()))
    }

    async fn delete_object(&self, key: &str) -> StorageResult<()> {
        let mut guard = self.inner.write().await;
        guard.remove(key);
        Ok(())
    }

    async fn list_objects(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let guard = self.inner.read().await;
        Ok(guard
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mem_backend_basic() {
        let backend = MemBackend::default();
        backend.put_object("logs/1", b"abc").await.unwrap();
        assert_eq!(backend.get_object("logs/1").await.unwrap(), b"abc");
        assert!(backend.list_objects("logs").await.unwrap().contains(&"logs/1".to_string()));
    }
}
