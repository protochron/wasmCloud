use anyhow::ensure;
use nkeys::XKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wascap::jwt::{validate_token, CapabilityProvider, Component, Host};

mod errors;
pub use crate::errors::*;

pub const WASMCLOUD_HOST_XKEY: &str = "WasmCloud-Host-Xkey";

/// The request context for retrieving a secret
#[derive(Serialize, Deserialize)]
pub struct Context {
    /// The component or provider's signed JWT.
    pub entity_jwt: String,
    /// The host's signed JWT.
    pub host_jwt: String,
}

impl Context {
    pub async fn valid_claims(&self) -> Result<(), ContextValidationError> {
        let component_valid = Self::valid_component(&self.entity_jwt);
        let provider_valid = Self::valid_provider(&self.entity_jwt);
        if component_valid.is_err() && provider_valid.is_err() {
            if let Err(e) = component_valid {
                return Err(ContextValidationError::InvalidComponentJWT(e.to_string()));
            } else {
                return Err(ContextValidationError::InvalidProviderJWT(
                    provider_valid.unwrap_err().to_string(),
                ));
            }
        }

        if Self::valid_host(&self.host_jwt).is_err() {
            return Err(ContextValidationError::InvalidHostJWT(
                Self::valid_host(&self.host_jwt).unwrap_err().to_string(),
            ));
        }
        Ok(())
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

    fn valid_host(token: &str) -> anyhow::Result<()> {
        let v = validate_token::<Host>(token)?;
        ensure!(!v.expired, "token expired at `{}`", v.expires_human);
        ensure!(
            !v.cannot_use_yet,
            "token cannot be used before `{}`",
            v.not_before_human
        );
        ensure!(v.signature_valid, "signature is not valid");
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct SecretResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<GetSecretError>,
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

pub trait SecretsAPI {
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
