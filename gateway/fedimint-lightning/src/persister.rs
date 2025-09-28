use aes_gcm::aead::Aead;
use aes_gcm::{KeyInit, Aes256Gcm, Nonce};
use getrandom;
use lightning::util::persist::KVStore;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tracing::warn;
use vss_client::client::VssClient;
use vss_client::error::VssError;
use vss_client::headers::FixedHeaders;
use vss_client::util::retry::ExponentialBackoffRetryPolicy;
use vss_client::types::{
    DeleteObjectRequest, GetObjectRequest, KeyValue, ListKeyVersionsRequest,
    PutObjectRequest,
};
use bitcoin::io;

#[derive(Clone)]
pub struct EncryptedVssStore {
    vss_client: Arc<VssClient<ExponentialBackoffRetryPolicy<VssError>>>,
    store_id: String,
    encryption_key: [u8; 32],
    fallback_dir: PathBuf,
    fallback_enabled: bool,
    fallback_active: Arc<std::sync::atomic::AtomicBool>,
}

impl EncryptedVssStore {
    pub fn new(
        vss_url: String,
        store_id: String,
        headers: HashMap<String, String>,
        encryption_key: [u8; 32],
        fallback_dir: PathBuf,
        fallback_enabled: bool,
    ) -> Self {
        let retry_policy = ExponentialBackoffRetryPolicy::new(Duration::from_millis(100));
        let header_provider = Arc::new(FixedHeaders::new(headers));
        let vss_client = VssClient::new_with_headers(vss_url, retry_policy, header_provider);
        Self {
            vss_client: Arc::new(vss_client),
            store_id,
            encryption_key,
            fallback_dir,
            fallback_enabled,
            fallback_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, io::Error> {
        if encrypted.len() < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid encrypted data",
            ));
        }
        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    fn combine_key(&self, namespace: &str, path: &str, key: &str) -> String {
        format!("{namespace}/{path}/{key}")
    }

    async fn try_vss_write(&self, full_key: &str, encrypted_value: &[u8]) -> Result<(), io::Error> {
        let kv = KeyValue {
            key: full_key.to_string(),
            version: -1, // Unconditional write
            value: encrypted_value.to_vec(),
        };
        let req = PutObjectRequest {
            store_id: self.store_id.clone(),
            transaction_items: vec![kv],
            delete_items: vec![],
            global_version: None,
        };
        self.vss_client
            .put_object(&req)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("VSS error: {e}")))?;

        Ok(())
    }

    async fn try_local_write(&self, full_key: &str, value: &[u8]) -> Result<(), io::Error> {
        let path = self.fallback_dir.join(full_key);
        fs::create_dir_all(path.parent().unwrap()).await?;
        fs::write(&path, value)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Local write failed: {e}")))
    }

    fn should_fallback(&self, err: &io::Error) -> bool {
        self.fallback_enabled
            && (err.to_string().contains("VSS") || err.to_string().contains("network"))
    }

    pub async fn reupload_fallback_data(&self) -> Result<(), io::Error> {
        let mut entries = fs::read_dir(&self.fallback_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let relative_path = path
                .strip_prefix(&self.fallback_dir)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
                .to_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid filename"))?
                .to_string();
            let bytes = fs::read(&path).await?;
            let encrypted = self.encrypt(&bytes)?;
            self.try_vss_write(&relative_path, &encrypted).await?;
            fs::remove_file(&path).await?;
        }
        Ok(())
    }
}

impl KVStore for EncryptedVssStore {
    fn read<'a, 'b, 'c>(
        &self,
        namespace: &'a str,
        path: &'b str,
        key: &'c str,
    ) -> Result<Vec<u8>, io::Error> {
        let full_key = self.combine_key(namespace, path, key);
        let req = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: full_key.clone(),
        };
        let rt = tokio::runtime::Handle::current();
        let result = rt.block_on(self.vss_client.get_object(&req));
        match result {
            Ok(resp) => {
                let encrypted = resp
                    .value
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Key not found"))?
                    .value;
                self.decrypt(&encrypted).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("Decryption failed: {e}"))
                })
            }
            Err(vss_err) => {
                if self.fallback_enabled
                    && self
                        .fallback_active
                        .load(std::sync::atomic::Ordering::Relaxed)
                {
                    let path = self.fallback_dir.join(&full_key);
                    std::fs::read(path)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Local read failed: {e}")))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("VSS read failed: {vss_err}"),
                    ))
                }
            }
        }
    }

    fn write<'a, 'b, 'c, 'd>(
        &self,
        namespace: &'a str,
        path: &'b str,
        key: &'c str,
        value: &'d [u8],
    ) -> Result<(), io::Error> {
        let full_key = self.combine_key(namespace, path, key);
        let encrypted = self.encrypt(value)?;
        let rt = tokio::runtime::Handle::current();
        match rt.block_on(self.try_vss_write(&full_key, &encrypted)) {
            Ok(_) => {
                self.fallback_active
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            Err(e) if self.should_fallback(&e) => {
                warn!("VSS write failed for '{}', using fallback: {}", full_key, e);
                self.fallback_active
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                rt.block_on(self.try_local_write(&full_key, value))
            }
            Err(e) => Err(e),
        }
    }

    fn remove<'a, 'b, 'c>(
        &self,
        namespace: &'a str,
        path: &'b str,
        key: &'c str,
        _lazy: bool,
    ) -> Result<(), io::Error> {
        let full_key = self.combine_key(namespace, path, key);
        let req = DeleteObjectRequest {
            store_id: self.store_id.clone(),
            key_value: Some(KeyValue {
                key: full_key,
                version: -1,
                value: vec![],
            }),
        };
        let rt = tokio::runtime::Handle::current();
        rt.block_on(self.vss_client.delete_object(&req))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("VSS delete failed: {e}")))?;
        
        Ok(())
    }

    fn list<'a, 'b>(
        &self,
        namespace: &'a str,
        path: &'b str,
    ) -> Result<Vec<String>, io::Error> {
        let prefix = format!("{namespace}/{path}");
        let mut keys = Vec::new();
        let mut page_token: Option<String> = None;
        let rt = tokio::runtime::Handle::current();
        loop {
            let req = ListKeyVersionsRequest {
                store_id: self.store_id.clone(),
                key_prefix: Some(prefix.clone()),
                page_size: Some(100),
                page_token,
            };
            let resp = rt
                .block_on(self.vss_client.list_key_versions(&req))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("VSS list failed: {e}")))?;
            keys.extend(
                resp.key_versions
                    .into_iter()
                    .map(|kv| {
                        kv.key
                            .strip_prefix(&prefix)
                            .map(|s| s.trim_start_matches('/').to_string())
                            .unwrap_or(kv.key)
                    })
                    .filter(|key| !key.is_empty()),
            );
            page_token = resp.next_page_token;
            if page_token.is_none() {
                break;
            }
        }
        Ok(keys)
    }
}