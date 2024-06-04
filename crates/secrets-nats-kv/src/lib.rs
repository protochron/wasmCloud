use anyhow::ensure;
use async_nats::jetstream::{
    self,
    kv::{Config, Entry, History},
};
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use nkeys::XKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use wascap::jwt::{CapabilityProvider, Host, TokenValidation};
use wascap::prelude::{validate_token, Claims, Component};

mod types;

pub const WASMCLOUD_HOST_XKEY: &str = "Wasmcloud-Host-Xkey";

#[derive(Serialize, Deserialize)]
pub struct Context {
    // The component or provider's signed JWT.
    pub entity_jwt: String,

    // TODO: think more about this. We can sign it with the host's public key, but I don't think
    // that actually buys us anything other than validating that the payload is signed by something
    // that has a nkey.
    // It also means that ex. a vault backend needs to consume both of these JWTs and mint an
    // intermediate one that merges the claims from both, which is tricky unless we create
    // per-connection JWTs for the vault backend. That's probably the most secure way to handle it,
    // but does that actually compromise the assumptions we're making?
    //
    // Scenario: App1 consists of a Postgres provider and a component connected to it, same as
    // App2. Both are deployed to different lattices, and therefore are operating in _different
    // security domains_. The Postgres provider is the same in both cases, but the components may
    // be different (or the same, it really doesn't matter). Problem: you want to write a policy
    // where App1 wouldn't be able to ever be deployed in a way where it could accidentally access
    // secrets meant for App2 _if you were to set them that way in a manifest_.
    // The only way I can see to prevent that (in vault) would be to bind the JWT backend to a set
    // of claims that includes runtime context information such as the lattice id and host labels.
    // The problem there is that we don't have a signed, verifiable place to originate that, and
    // even if we did, we still need to issue a new JWT from the secrets backend that merges the
    // claims from both the build context (component or provider claims) and the runtime context
    // (effectively host claims).
    //
    // What we _can_ do is add an additional api alongside whatever handles the lattice API auth
    // callout flow that dispenses a signed JWT for a host issued by it's account key. That JWT
    // would include the host labels and other metadata. The host itself could mint a HostInfo jwt
    // as outlined below with the host labels and lattice id, and then the secrets backend could
    // verify that the host was issued by a known account key by presenting it's signed copy of the
    // host JWT.
    pub host_jwt: String,
    // TODO how in the world do we verify this?
    //pub application_name: String,
}

impl Context {
    pub async fn valid_host_claim(&self) {}
}

/// Duplicate of the HostInfo struct in the wasmcloud host crate
#[derive(Serialize, Deserialize)]
pub struct HostInfo {
    /// The public key ID of the host
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// The name of the lattice the host is running in
    pub lattice: String,
    /// The labels associated with the host
    pub labels: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct SecretRequest {
    // The name of the secret
    pub name: String,
    // The version of the secret
    pub version: Option<String>,
    pub context: Context,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Secret {
    pub name: String,
    pub version: String,
    pub string_secret: Option<String>,
    pub binary_secret: Option<Vec<u8>>,
}

#[derive(Error, Debug, Serialize, Deserialize)]
enum GetSecretError {
    #[error("Invalid Entity JWT: {0}")]
    InvalidEntityJWT(String),
    #[error("Invalid Host JWT: {0}")]
    InvalidHostJWT(String),
    #[error("Secret not found")]
    SecretNotFound,
    #[error("Invalid XKey")]
    InvalidXKey,
    #[error("Error encrypting secret")]
    EncryptionError,
    #[error("Error decrypting secret")]
    DecryptionError,
    #[error("Error fetching secret: {0}")]
    UpstreamError(String),
    #[error("Error fetching secret: unauthorized")]
    Unauthorized,
}

#[derive(Serialize, Deserialize, Default)]
pub struct SecretResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<GetSecretError>,
}

impl From<GetSecretError> for SecretResponse {
    fn from(e: GetSecretError) -> Self {
        SecretResponse {
            error: Some(e),
            ..Default::default()
        }
    }
}

impl From<SecretResponse> for Bytes {
    fn from(resp: SecretResponse) -> Self {
        let encoded = serde_json::to_vec(&resp).unwrap();
        Bytes::from(encoded)
    }
}

trait SecretsAPI {
    // Returns the secret value for the given secret name
    async fn get(
        &self,
        // The name of the secret
        secret_name: &str,
        // The version of the secret
        version: Option<String>,
        // The context of the requestor
        context: Context,
    ) -> Result<SecretResponse, GetSecretError>;
    // Returns the server's public XKey
    fn server_xkey(&self) -> XKey;
}

// Internal types

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
}

//#[derive(Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq, Debug)]
//pub struct MappingKey {
//    entity: String,
//    #[serde(default)]
//    labels: std::collections::BTreeSet<String>,
//}

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
    pub async fn run(&self) -> anyhow::Result<()> {
        let subject = format!("{}.{}.>", &self.subject_base, self.name);
        info!(subject, "Starting listener");
        // TODO: queue subscribe
        // TODO: version the subject
        let mut sub = self.client.subscribe(subject.clone()).await?;

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

                    let response = self
                        .get(&secret_req.name, secret_req.version, secret_req.context)
                        .await;
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
        }
    }
}

impl SecretsAPI for Api {
    async fn get(
        &self,
        // The name of the secret
        secret_name: &str,
        // The version of the secret
        version: Option<String>,
        // The context of the requestor
        context: Context,
    ) -> Result<SecretResponse, GetSecretError> {
        // First validate the entity JWT
        if valid_component(&context.entity_jwt).is_err()
            && valid_provider(&context.entity_jwt).is_err()
        {
            let err = valid_component(&context.entity_jwt).unwrap_err();
            error!(error=%err, "failed to validate");
            return Err(GetSecretError::InvalidEntityJWT(err.to_string()));
        }

        // Next, validate the host JWT
        let host_claims: Claims<Host> = Claims::decode(&context.host_jwt)
            .map_err(|e| GetSecretError::InvalidEntityJWT(e.to_string()))?;
        if let Err(e) = validate_token::<Host>(&context.host_jwt) {
            return Err(GetSecretError::InvalidHostJWT(e.to_string()));
        };

        // TODO: this shouldn't be possible in the future, but until we have a way of telling
        // dynamically issuing host JWTs for this purpose we can just warn about it.
        if host_claims.issuer.starts_with('N') {
            warn!("Host JWT issued by a non-account key");
        }

        // Now that we have established both JWTs are valid, we can go ahead and retrieve the
        // secret
        let claims: Claims<Component> = Claims::decode(&context.entity_jwt)
            .map_err(|e| GetSecretError::InvalidEntityJWT(e.to_string()))?;
        let subject = claims.subject;
        let mapping = self.secrets_mapping.read().await;
        let map = mapping.get(&subject).ok_or(GetSecretError::Unauthorized)?;

        if !map.contains(secret_name) {
            return Err(GetSecretError::Unauthorized);
        }

        let js = jetstream::new(self.client.clone());
        let secrets = js
            .get_key_value(&self.bucket)
            .await
            .map_err(|e| GetSecretError::UpstreamError(e.to_string()))?;

        let entry = match version {
            Some(v) => {
                let revision = str::parse::<u64>(&v).unwrap();
                let mut key_hist = secrets
                    .history(secret_name)
                    .await
                    .map_err(|e| GetSecretError::UpstreamError(e.to_string()))?;
                find_key_rev(&mut key_hist, revision).await
            }
            None => secrets
                .entry(secret_name)
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

fn valid_component(token: &str) -> anyhow::Result<()> {
    let v = validate_token::<Component>(token)?;
    ensure!(!v.expired, "token expired at `{}`", v.expires_human);
    ensure!(
        !v.cannot_use_yet,
        "token cannot be used before `{}`",
        v.not_before_human
    );
    ensure!(v.signature_valid, "signature is not valid");
    Ok(())
}

fn valid_provider(token: &str) -> anyhow::Result<()> {
    let v = validate_token::<CapabilityProvider>(token)?;
    ensure!(!v.expired, "token expired at `{}`", v.expires_human);
    ensure!(
        !v.cannot_use_yet,
        "token cannot be used before `{}`",
        v.not_before_human
    );
    ensure!(v.signature_valid, "signature is not valid");

    Ok(())
}

async fn find_key_rev(h: &mut History, revision: u64) -> Option<Entry> {
    while let Some(entry) = h.next().await {
        if let Ok(entry) = entry {
            if entry.revision == revision {
                return Some(entry);
            }
        }
    }
    None
}
