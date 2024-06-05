use anyhow::ensure;
use async_nats::jetstream::{
    self,
    kv::{Config, Entry, History, Store},
};
use async_trait::async_trait;
use futures::StreamExt;
use nkeys::XKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use wascap::jwt::{CapabilityProvider, Host};
use wascap::prelude::{validate_token, Claims, Component};

use wasmcloud_secrets_types::*;

pub struct Api {
    // The server's public XKey
    server_xkey: XKey,
    encryption_xkey: XKey,
    pub client: async_nats::Client,
    subject_base: String,
    pub name: String,
    pub bucket: String,
    secrets_mapping: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    max_secret_history: usize,
    queue_base: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PutSecretResponse {
    pub revision: u64,
}

impl From<u64> for PutSecretResponse {
    fn from(r: u64) -> Self {
        Self { revision: r }
    }
}

impl Api {
    fn queue_name(&self) -> String {
        format!("{}.{}", self.queue_base, self.name)
    }

    async fn state_bucket(&self) -> anyhow::Result<Store> {
        let name = format!("SECRETS_{}_state", self.name);
        let js = jetstream::new(self.client.clone());
        js.get_key_value(&name).await.map_err(|e| e.into())
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let queue_name = self.queue_name();
        let subject = format!("{}.{}.>", &self.subject_base, self.name);
        info!(subject, "Starting listener");
        // TODO: version the subject
        let mut sub = self
            .client
            .queue_subscribe(subject.clone(), queue_name)
            .await?;

        let js = jetstream::new(self.client.clone());
        let _store = match js.get_key_value(&self.bucket).await {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == jetstream::context::KeyValueErrorKind::GetBucket {
                    js.create_key_value(Config {
                        bucket: self.bucket.clone(),
                        description: "Secrets store".to_string(),
                        compression: true,
                        history: self.max_secret_history as i64,
                        ..Default::default()
                    })
                    .await?
                } else {
                    return Err(e.into());
                }
            }
        };

        let state_name = format!("SECRETS_{}_state", self.name);
        let _state_store = match js.get_key_value(&state_name).await {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == jetstream::context::KeyValueErrorKind::GetBucket {
                    js.create_key_value(Config {
                        bucket: state_name.clone(),
                        description: "Secrets state store".to_string(),
                        compression: true,
                        ..Default::default()
                    })
                    .await?
                } else {
                    return Err(e.into());
                }
            }
        };

        while let Some(msg) = sub.next().await {
            let reply = match msg.reply {
                Some(reply) => reply,
                None => continue,
            };

            let parts: Vec<&str> = msg.subject.split('.').collect();
            if parts.len() < 3 {
                let _ = self.client.publish(reply, "invalid subject".into()).await;
                continue;
            }
            let op = parts[2];

            match op {
                "server_xkey" => {
                    let _ = self
                        .client
                        .publish(reply, self.server_xkey().public_key().into())
                        .await;
                }
                "get" => {
                    let payload = msg.payload;
                    if payload.is_empty() {
                        let _ = self
                            .client
                            .publish(reply, "no payload provided".into())
                            .await;
                        continue;
                    }

                    if msg.headers.is_none() {
                        let _ = self
                            .client
                            .publish(reply, "no headers provided".into())
                            .await;
                        continue;
                    }

                    let headers = msg.headers.unwrap();
                    let host_key = match headers.get(WASMCLOUD_HOST_XKEY) {
                        None => {
                            let _ = self
                                .client
                                .publish(
                                    reply,
                                    SecretResponse::from(GetSecretError::InvalidXKey).into(),
                                )
                                .await;
                            continue;
                        }
                        Some(key) => key,
                    };

                    let k = XKey::from_public_key(host_key.as_str()).unwrap();
                    let payload = match self.server_xkey.open(&payload, &k) {
                        Ok(p) => p,
                        Err(_e) => {
                            let _ = self
                                .client
                                .publish(
                                    reply,
                                    SecretResponse::from(GetSecretError::DecryptionError).into(),
                                )
                                .await;
                            continue;
                        }
                    };
                    let secret_req: SecretRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            // TODO real error
                            let _ = self.client.publish(reply, e.to_string().into()).await;
                            continue;
                        }
                    };

                    let response = self.get(secret_req).await;
                    match response {
                        Ok(resp) => {
                            let encoded = serde_json::to_vec(&resp).unwrap();
                            let encrypted = match self.server_xkey.seal(&encoded, &k) {
                                Ok(e) => e,
                                Err(_e) => {
                                    let _ = self
                                        .client
                                        .publish(
                                            reply,
                                            SecretResponse::from(GetSecretError::EncryptionError)
                                                .into(),
                                        )
                                        .await;
                                    continue;
                                }
                            };

                            let mut headers = async_nats::HeaderMap::new();
                            headers.insert(
                                WASMCLOUD_HOST_XKEY,
                                self.server_xkey().public_key().as_str(),
                            );

                            let _ = self
                                .client
                                .publish_with_headers(reply, headers, encrypted.into())
                                .await;
                        }
                        Err(e) => {
                            let _ = self.client.publish(reply, e.to_string().into()).await;
                        }
                    }
                }
                // Custom handlers
                "add_mapping" => {
                    let entity = match parts.get(3) {
                        Some(e) => e,
                        None => {
                            let _ = self
                                .client
                                .publish(reply, "no entity provided".into())
                                .await;
                            continue;
                        }
                    };

                    let payload = msg.payload;
                    let values: HashSet<String> = match serde_json::from_slice(&payload) {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = self.client.publish(reply, e.to_string().into()).await;
                            continue;
                        }
                    };
                    self.add_mapping(entity.to_string(), values).await;
                    let _ = self.client.publish(reply, "ok".into()).await;
                }
                "remove_mapping" => {
                    let entity = match parts.get(3) {
                        Some(e) => e,
                        None => {
                            let _ = self
                                .client
                                .publish(
                                    reply,
                                    "no provider or component public key provided".into(),
                                )
                                .await;
                            continue;
                        }
                    };

                    let payload = msg.payload;
                    let values: HashSet<String> = match serde_json::from_slice(&payload) {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = self.client.publish(reply, e.to_string().into()).await;
                            continue;
                        }
                    };
                    self.remove_mapping(entity.to_string(), values).await;
                    let _ = self.client.publish(reply, "ok".into()).await;
                }
                "put_secret" => {
                    let payload = msg.payload;
                    if payload.is_empty() {
                        let _ = self
                            .client
                            .publish(reply, "no payload provided".into())
                            .await;
                        continue;
                    }

                    if msg.headers.is_none() {
                        let _ = self
                            .client
                            .publish(reply, "no headers provided".into())
                            .await;
                        continue;
                    }

                    let headers = msg.headers.unwrap();
                    let host_key = match headers.get(WASMCLOUD_HOST_XKEY) {
                        None => {
                            let _ = self
                                .client
                                .publish(
                                    reply,
                                    SecretResponse::from(GetSecretError::InvalidXKey).into(),
                                )
                                .await;
                            continue;
                        }
                        Some(key) => key,
                    };

                    let k = XKey::from_public_key(host_key.as_str()).unwrap();
                    let payload = match self.server_xkey.open(&payload, &k) {
                        Ok(p) => p,
                        Err(_e) => {
                            let _ = self
                                .client
                                .publish(
                                    reply,
                                    SecretResponse::from(GetSecretError::DecryptionError).into(),
                                )
                                .await;
                            continue;
                        }
                    };

                    let secret: Secret = match serde_json::from_slice(&payload) {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = self.client.publish(reply, e.to_string().into()).await;
                            continue;
                        }
                    };

                    let store = js.get_key_value(&self.bucket).await?;
                    let encrypted_value = if let Some(s) = secret.string_secret {
                        self.encryption_xkey
                            .seal(s.as_bytes(), &self.encryption_xkey)
                            .unwrap()
                    } else if let Some(b) = secret.binary_secret {
                        self.encryption_xkey
                            .seal(&b, &self.encryption_xkey)
                            .unwrap()
                    } else {
                        let _ = self
                            .client
                            .publish(reply, "no secret provided".into())
                            .await;
                        continue;
                    };

                    match store.put(secret.name, encrypted_value.into()).await {
                        Ok(revision) => {
                            let resp = PutSecretResponse::from(revision);
                            let _ = self
                                .client
                                .publish(reply, serde_json::to_string(&resp).unwrap().into())
                                .await;
                        }
                        Err(e) => {
                            let _ = self.client.publish(reply, e.to_string().into()).await;
                        }
                    };
                }
                o => {
                    let _ = self
                        .client
                        .publish(reply, format!("unknown operation {o}").into())
                        .await;
                }
            }
        }

        Ok(())
    }

    // TODO: persist and load all this
    // TODO: add a way to specify labels that should apply to this mapping. That way you can
    // provide host labels that should grant an entity access to a secret.
    async fn add_mapping(&self, entity: String, values: HashSet<String>) {
        let mut map = self.secrets_mapping.write().await;
        if map.contains_key(&entity) {
            let vals = map.get_mut(&entity).unwrap();
            vals.extend(values);
            return;
        }
        map.insert(entity, values);
    }

    async fn remove_mapping(&self, entity: String, values: HashSet<String>) {
        let mut map = self.secrets_mapping.write().await;
        if map.contains_key(&entity) {
            let vals = map.get_mut(&entity).unwrap();
            vals.retain(|v| !values.contains(v));
        }
    }

    pub fn new(
        server_xkey: XKey,
        encryption_xkey: XKey,
        client: async_nats::Client,
        subject_base: String,
        name: String,
        bucket: String,
        max_secret_history: usize,
        queue_base: String,
    ) -> Self {
        Self {
            server_xkey,
            encryption_xkey,
            client,
            subject_base,
            name,
            bucket,
            secrets_mapping: Arc::new(RwLock::new(HashMap::new())),
            max_secret_history,
            queue_base,
        }
    }
}

#[async_trait]
impl SecretsAPI for Api {
    async fn get(&self, request: SecretRequest) -> Result<SecretResponse, GetSecretError> {
        // First validate the entity JWT
        if let Err(e) = request.context.valid_claims() {
            return Err(GetSecretError::InvalidEntityJWT(e.to_string()));
        }

        // Next, validate the host JWT
        let host_claims: Claims<Host> = Claims::decode(&request.context.host_jwt)
            .map_err(|e| GetSecretError::InvalidEntityJWT(e.to_string()))?;
        if let Err(e) = validate_token::<Host>(&request.context.host_jwt) {
            return Err(GetSecretError::InvalidHostJWT(e.to_string()));
        };

        // TODO: this shouldn't be possible in the future, but until we have a way of telling
        // dynamically issuing host JWTs for this purpose we can just warn about it.
        if host_claims.issuer.starts_with('N') {
            warn!("Host JWT issued by a non-account key");
        }

        // Now that we have established both JWTs are valid, we can go ahead and retrieve the
        // secret
        let claims: Claims<Component> = Claims::decode(&request.context.entity_jwt)
            .map_err(|e| GetSecretError::InvalidEntityJWT(e.to_string()))?;
        let subject = claims.subject;
        let mapping = self.secrets_mapping.read().await;
        let map = mapping.get(&subject).ok_or(GetSecretError::Unauthorized)?;

        if !map.contains(&request.name) {
            return Err(GetSecretError::Unauthorized);
        }

        let js = jetstream::new(self.client.clone());
        let secrets = js
            .get_key_value(&self.bucket)
            .await
            .map_err(|e| GetSecretError::UpstreamError(e.to_string()))?;

        let entry = match &request.version {
            Some(v) => {
                let revision = str::parse::<u64>(&v).unwrap();

                let mut key_hist = secrets
                    .history(&request.name)
                    .await
                    .map_err(|e| GetSecretError::UpstreamError(e.to_string()))?;
                find_key_rev(&mut key_hist, revision).await
            }
            None => secrets
                .entry(&request.name)
                .await
                .map_err(|e| GetSecretError::UpstreamError(e.to_string()))?,
        };

        if entry.is_none() {
            return Err(GetSecretError::SecretNotFound);
        }
        // SAFETY: entry is not None, we just verified that
        let entry = entry.unwrap();

        let mut secret = Secret {
            name: entry.key,
            version: entry.revision.to_string(),
            ..Default::default()
        };

        let decrypted = self
            .encryption_xkey
            .open(&entry.value, &self.encryption_xkey)
            .map_err(|_| GetSecretError::DecryptionError)?;

        match String::from_utf8(decrypted) {
            Ok(s) => {
                secret.string_secret = Some(s);
            }
            Err(_) => {
                secret.binary_secret = Some(entry.value.to_vec());
            }
        };

        let response = SecretResponse {
            secret: Some(secret),
            ..Default::default()
        };
        Ok(response)
    }

    fn server_xkey(&self) -> XKey {
        let xkey = XKey::from_public_key(self.server_xkey.public_key().as_str()).unwrap();
        xkey
    }
}

async fn find_key_rev<'a>(h: &mut History, revision: u64) -> Option<Entry> {
    while let Some(entry) = h.next().await {
        if let Ok(entry) = entry {
            if entry.revision == revision {
                return Some(entry);
            }
        }
    }
    None
}
