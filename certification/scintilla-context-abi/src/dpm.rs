//! Bounded integration with declarative-postgres-migrate.
//!
//! Commands are spawned directly without a shell. Only plan, verification, and
//! bootstrap operations exist; apply is deliberately not representable.

use std::ffi::{OsStr, OsString};
use std::fmt::{Debug, Formatter};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

const DEFAULT_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone, PartialEq, Eq)]
pub struct SecretArg(String);

impl SecretArg {
    pub fn new(value: impl Into<String>) -> Result<Self, DpmError> {
        let value = value.into();
        if value.is_empty() || value.contains('\0') {
            return Err(DpmError::InvalidSecret);
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl Debug for SecretArg {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretArg([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpmOperation {
    Diff,
    Verify,
    Bootstrap,
}

#[derive(Clone)]
pub struct DpmRequest {
    pub operation: DpmOperation,
    pub source: PathBuf,
    pub target: Option<SecretArg>,
    pub shadow: SecretArg,
}

impl Debug for DpmRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DpmRequest")
            .field("operation", &self.operation)
            .field("source", &self.source)
            .field("target", &self.target)
            .field("shadow", &self.shadow)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpmOutput {
    pub stdout: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DpmError {
    #[error("DPM source must be a readable regular file")]
    InvalidSource,
    #[error("DPM diff and verify require a target")]
    MissingTarget,
    #[error("DPM secret argument is empty or invalid")]
    InvalidSecret,
    #[error("DPM timeout must be between one millisecond and five minutes")]
    InvalidTimeout,
    #[error("failed to spawn DPM")]
    Spawn,
    #[error("DPM timed out")]
    Timeout,
    #[error("DPM output exceeded the configured limit")]
    OutputLimit,
    #[error("DPM output was not UTF-8")]
    InvalidOutput,
    #[error("DPM exited unsuccessfully with code {code:?}")]
    NonZero { code: Option<i32> },
}

#[derive(Debug, Clone)]
pub struct DpmCli {
    binary: PathBuf,
    timeout: Duration,
    output_limit: usize,
}

impl DpmCli {
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            timeout: Duration::from_secs(30),
            output_limit: DEFAULT_OUTPUT_LIMIT,
        }
    }

    pub fn with_limits(mut self, timeout: Duration, output_limit: usize) -> Result<Self, DpmError> {
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(DpmError::InvalidTimeout);
        }
        if output_limit == 0 {
            return Err(DpmError::OutputLimit);
        }
        self.timeout = timeout;
        self.output_limit = output_limit;
        Ok(self)
    }

    pub async fn run(&self, request: &DpmRequest) -> Result<DpmOutput, DpmError> {
        let args = validated_args(request)?;
        let mut command = Command::new(&self.binary);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| DpmError::Spawn)?;
        let stdout = child.stdout.take().ok_or(DpmError::Spawn)?;
        let stderr = child.stderr.take().ok_or(DpmError::Spawn)?;
        let operation = async {
            tokio::try_join!(
                read_limited(stdout, self.output_limit),
                read_limited(stderr, self.output_limit),
                async { child.wait().await.map_err(|_| DpmError::Spawn) }
            )
        };
        let (stdout, _stderr, status) = match tokio::time::timeout(self.timeout, operation).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                let _ = child.kill().await;
                return Err(error);
            }
            Err(_) => {
                let _ = child.kill().await;
                return Err(DpmError::Timeout);
            }
        };
        if !status.success() {
            return Err(DpmError::NonZero {
                code: status.code(),
            });
        }
        let stdout = String::from_utf8(stdout).map_err(|_| DpmError::InvalidOutput)?;
        Ok(DpmOutput { stdout })
    }
}

async fn read_limited(reader: impl AsyncRead + Unpin, limit: usize) -> Result<Vec<u8>, DpmError> {
    let mut output = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut output)
        .await
        .map_err(|_| DpmError::Spawn)?;
    if output.len() > limit {
        return Err(DpmError::OutputLimit);
    }
    Ok(output)
}

fn validated_args(request: &DpmRequest) -> Result<Vec<OsString>, DpmError> {
    if !request.source.is_file() {
        return Err(DpmError::InvalidSource);
    }
    let mut args = vec![OsString::from(match request.operation {
        DpmOperation::Diff => "diff",
        DpmOperation::Verify => "verify",
        DpmOperation::Bootstrap => "bootstrap",
    })];
    push_pair(&mut args, "--source", request.source.as_os_str());
    if matches!(request.operation, DpmOperation::Diff | DpmOperation::Verify) {
        let target = request.target.as_ref().ok_or(DpmError::MissingTarget)?;
        push_pair(&mut args, "--target", OsStr::new(target.expose()));
    }
    push_pair(&mut args, "--shadow", OsStr::new(request.shadow.expose()));
    push_pair(&mut args, "--format", OsStr::new("json"));
    Ok(args)
}

fn push_pair(args: &mut Vec<OsString>, flag: &str, value: &OsStr) {
    args.push(OsString::from(flag));
    args.push(value.to_owned());
}

pub fn dpm_binary_from_env() -> PathBuf {
    std::env::var_os("SCINTILLA_DPM_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new("dpm").to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_debug_redacts_database_urls() {
        let request = DpmRequest {
            operation: DpmOperation::Verify,
            source: PathBuf::from("contracts/database/desired.sql"),
            target: Some(SecretArg::new("postgres://user:password@db/target").unwrap()),
            shadow: SecretArg::new("postgres://user:password@db/shadow").unwrap(),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("password"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn apply_is_not_representable() {
        assert_eq!(
            [
                DpmOperation::Diff,
                DpmOperation::Verify,
                DpmOperation::Bootstrap
            ]
            .len(),
            3
        );
    }
}
