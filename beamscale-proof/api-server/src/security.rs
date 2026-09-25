use axum::http::{HeaderMap, StatusCode};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    env,
    fs::{self, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct SecurityClient {
    client: Client,
    auth_introspection_url: String,
    security_state_url: String,
    security_state_service_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub user_id: String,
    tenant_ids: HashSet<String>,
}

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("missing or invalid bearer authorization")]
    Unauthorized,
    #[error("principal is not authorized for tenant `{0}`")]
    ForbiddenTenant(String),
    #[error("principal or tenant is security-blocked; incident_id={0:?}")]
    Blocked(Option<String>),
    #[error("security provider unavailable: {0}")]
    Unavailable(String),
    #[error("security provider returned invalid data: {0}")]
    InvalidProviderResponse(String),
}

impl SecurityError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::ForbiddenTenant(_) => StatusCode::FORBIDDEN,
            Self::Blocked(_) => StatusCode::LOCKED,
            Self::Unavailable(_) | Self::InvalidProviderResponse(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct IntrospectionResponse {
    active: bool,
    user_id: String,
    #[serde(default)]
    tenant_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SecurityStateRequest<'a> {
    user_id: &'a str,
    tenant_id: &'a str,
}

#[derive(Debug, Deserialize)]
struct SecurityStateResponse {
    blocked: bool,
    #[serde(default)]
    incident_id: Option<String>,
}

impl SecurityClient {
    pub fn from_env(client: Client) -> Result<Self, SecurityError> {
        let auth_introspection_url = required_url("BMSCL_AUTH_INTROSPECTION_URL")?;
        let security_state_url = required_url("BMSCL_SECURITY_STATE_URL")?;
        let security_state_service_token =
            required_secret_file("BMSCL_SECURITY_STATE_SERVICE_TOKEN_FILE", 32, 4096)?;
        Ok(Self {
            client,
            auth_introspection_url,
            security_state_url,
            security_state_service_token,
        })
    }

    pub async fn authorize(
        &self,
        headers: &HeaderMap,
        tenant_id: &str,
    ) -> Result<Principal, SecurityError> {
        let token = bearer_token(headers)?;
        let principal = self.introspect(token).await?;
        if !principal.tenant_ids.contains(tenant_id) {
            return Err(SecurityError::ForbiddenTenant(tenant_id.to_owned()));
        }
        self.ensure_unblocked(&principal.user_id, tenant_id).await?;
        Ok(principal)
    }

    async fn introspect(&self, token: &str) -> Result<Principal, SecurityError> {
        let response = self
            .client
            .post(&self.auth_introspection_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|error| SecurityError::Unavailable(error.to_string()))?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
        {
            return Err(SecurityError::Unauthorized);
        }
        if !response.status().is_success() {
            return Err(SecurityError::Unavailable(format!(
                "auth introspection returned HTTP {}",
                response.status()
            )));
        }

        let body = response
            .json::<IntrospectionResponse>()
            .await
            .map_err(|error| SecurityError::InvalidProviderResponse(error.to_string()))?;
        if !body.active {
            return Err(SecurityError::Unauthorized);
        }
        validate_subject("user_id", &body.user_id)?;
        let mut tenant_ids = HashSet::new();
        for tenant_id in body.tenant_ids {
            validate_subject("tenant_id", &tenant_id)?;
            tenant_ids.insert(tenant_id);
        }
        Ok(Principal {
            user_id: body.user_id,
            tenant_ids,
        })
    }

    async fn ensure_unblocked(&self, user_id: &str, tenant_id: &str) -> Result<(), SecurityError> {
        let response = self
            .client
            .post(&self.security_state_url)
            .bearer_auth(&self.security_state_service_token)
            .json(&SecurityStateRequest { user_id, tenant_id })
            .send()
            .await
            .map_err(|error| SecurityError::Unavailable(error.to_string()))?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
        {
            return Err(SecurityError::Unavailable(
                "security-state service authentication rejected".to_owned(),
            ));
        }
        if !response.status().is_success() {
            return Err(SecurityError::Unavailable(format!(
                "security-state lookup returned HTTP {}",
                response.status()
            )));
        }
        let body = response
            .json::<SecurityStateResponse>()
            .await
            .map_err(|error| SecurityError::InvalidProviderResponse(error.to_string()))?;
        if body.blocked {
            if let Some(incident_id) = body.incident_id.as_deref() {
                validate_subject("incident_id", incident_id)?;
            }
            return Err(SecurityError::Blocked(body.incident_id));
        }
        Ok(())
    }
}

fn required_url(name: &str) -> Result<String, SecurityError> {
    let value =
        env::var(name).map_err(|_| SecurityError::Unavailable(format!("{name} is required")))?;
    let parsed = reqwest::Url::parse(&value)
        .map_err(|error| SecurityError::Unavailable(format!("invalid {name}: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(SecurityError::Unavailable(format!(
            "{name} must be an absolute HTTP(S) URL"
        )));
    }
    Ok(value)
}

fn required_secret_file(
    name: &str,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<String, SecurityError> {
    let path = env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| SecurityError::Unavailable(format!("{name} is required")))?;
    let before = validate_secret_path(name, &path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(&path).map_err(|error| {
        SecurityError::Unavailable(format!("open {name} {}: {error}", path.display()))
    })?;
    let opened = file
        .metadata()
        .map_err(|error| SecurityError::Unavailable(format!("read {name} metadata: {error}")))?;
    validate_open_secret_metadata(name, &opened)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(SecurityError::Unavailable(format!(
                "{name} changed while being opened"
            )));
        }
    }

    let mut body = Vec::new();
    (&mut file)
        .take((max_bytes as u64) + 1)
        .read_to_end(&mut body)
        .map_err(|error| {
            SecurityError::Unavailable(format!("read {name} {}: {error}", path.display()))
        })?;
    while matches!(body.last(), Some(b'\n' | b'\r')) {
        body.pop();
    }
    if body.len() < min_bytes
        || body.len() > max_bytes
        || body.iter().any(|byte| byte.is_ascii_control())
    {
        return Err(SecurityError::Unavailable(format!(
            "{name} must contain {min_bytes}-{max_bytes} non-control bytes"
        )));
    }
    String::from_utf8(body)
        .map_err(|_| SecurityError::Unavailable(format!("{name} must contain UTF-8 text")))
}

fn validate_secret_path(name: &str, path: &Path) -> Result<fs::Metadata, SecurityError> {
    if !path.is_absolute() {
        return Err(SecurityError::Unavailable(format!(
            "{name} must be an absolute path"
        )));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| SecurityError::Unavailable(format!("read {name} metadata: {error}")))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(SecurityError::Unavailable(format!(
            "{name} must reference a regular non-symlink file"
        )));
    }
    validate_open_secret_metadata(name, &metadata)?;
    Ok(metadata)
}

fn validate_open_secret_metadata(name: &str, metadata: &fs::Metadata) -> Result<(), SecurityError> {
    if !metadata.file_type().is_file() {
        return Err(SecurityError::Unavailable(format!(
            "{name} must reference a regular file"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(SecurityError::Unavailable(format!(
                "{name} file must not be group/world accessible"
            )));
        }
    }
    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, SecurityError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(SecurityError::Unauthorized)?
        .to_str()
        .map_err(|_| SecurityError::Unauthorized)?;
    let token = value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .ok_or(SecurityError::Unauthorized)?;
    if token.len() > 16 * 1024 || token.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(SecurityError::Unauthorized);
    }
    Ok(token)
}

fn validate_subject(label: &str, value: &str) -> Result<(), SecurityError> {
    let valid = !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(SecurityError::InvalidProviderResponse(format!(
            "invalid {label}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_parser_rejects_non_bearer_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic Zm9vOmJhcg==".parse().unwrap(),
        );
        assert!(matches!(
            bearer_token(&headers),
            Err(SecurityError::Unauthorized)
        ));
    }

    #[test]
    fn provider_subjects_must_be_path_safe_identifiers() {
        assert!(validate_subject("user_id", "usr_123").is_ok());
        assert!(validate_subject("user_id", "../root").is_err());
        assert!(validate_subject("tenant_id", "acme-prod").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_must_be_private_and_non_symlink() {
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("bmscl-security-secret-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let secret = root.join("token");
        fs::write(&secret, b"01234567890123456789012345678901\n").unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_secret_path("TEST", &secret).is_ok());

        fs::set_permissions(&secret, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(validate_secret_path("TEST", &secret).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
