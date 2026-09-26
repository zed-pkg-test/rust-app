pub mod artifact_receive;

use serde_json::Value;
use std::io;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestIdentity {
    pub execution_class: String,
    pub execution_backend: String,
    pub tenant_id: String,
    pub runtime_epoch: u64,
}

impl GuestIdentity {
    pub fn from_cmdline(cmdline: &str) -> io::Result<Self> {
        let execution_class = cmdline_value(cmdline, "bmscl.execution_class")?;
        let execution_backend = cmdline_value(cmdline, "bmscl.execution_backend")?;
        let tenant_id = cmdline_value(cmdline, "bmscl.tenant_id")?;
        let runtime_epoch = cmdline_value(cmdline, "bmscl.runtime_epoch")?
            .parse::<u64>()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid bmscl.runtime_epoch")
            })?;

        if !matches!(execution_class.as_str(), "phoenix" | "durable_actor") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest execution class must be phoenix or durable_actor",
            ));
        }
        if execution_backend != "firecracker" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest execution backend must be firecracker",
            ));
        }
        if !valid_identity_component(&tenant_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid guest tenant identity",
            ));
        }
        Ok(Self {
            execution_class,
            execution_backend,
            tenant_id,
            runtime_epoch,
        })
    }

    pub fn validate_fields(
        &self,
        execution_class: &str,
        execution_backend: &str,
        tenant_id: &str,
        runtime_epoch: u64,
    ) -> Result<(), String> {
        if execution_class != self.execution_class
            || execution_backend != self.execution_backend
            || tenant_id != self.tenant_id
            || runtime_epoch != self.runtime_epoch
        {
            return Err("guest request identity does not match boot identity".into());
        }
        Ok(())
    }

    pub fn validate_frame(&self, bytes: &[u8]) -> Result<(), String> {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|err| format!("invalid guest request json: {err}"))?;
        let class = value
            .get("execution_class")
            .and_then(Value::as_str)
            .ok_or_else(|| "guest request is missing execution_class".to_string())?;
        let backend = value
            .get("execution_backend")
            .and_then(Value::as_str)
            .ok_or_else(|| "guest request is missing execution_backend".to_string())?;
        let tenant_id = value
            .get("tenant_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "guest request is missing tenant_id".to_string())?;
        let runtime_epoch = value
            .get("runtime_epoch")
            .and_then(Value::as_u64)
            .ok_or_else(|| "guest request is missing runtime_epoch".to_string())?;
        self.validate_fields(class, backend, tenant_id, runtime_epoch)
    }
}

fn cmdline_value(cmdline: &str, key: &str) -> io::Result<String> {
    let prefix = format!("{key}=");
    cmdline
        .split_whitespace()
        .find_map(|item| item.strip_prefix(&prefix))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing guest boot identity field {key}"),
            )
        })
}

fn valid_identity_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_frame<R>(reader: &mut R, max_frame_bytes: usize) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u32().await? as usize;
    if len == 0 || len > max_frame_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid frame length {len}"),
        ));
    }
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}

pub async fn write_frame<W>(writer: &mut W, bytes: &[u8], max_frame_bytes: usize) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if bytes.is_empty() || bytes.len() > max_frame_bytes || bytes.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid frame length {}", bytes.len()),
        ));
    }
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(bytes).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    #[test]
    fn parses_and_enforces_guest_boot_identity() {
        let identity = GuestIdentity::from_cmdline(
            "console=ttyS0 bmscl.execution_class=phoenix bmscl.execution_backend=firecracker \
             bmscl.tenant_id=tenant-1 bmscl.runtime_epoch=7",
        )
        .unwrap();
        assert_eq!(identity.execution_class, "phoenix");
        assert!(identity
            .validate_fields("phoenix", "firecracker", "tenant-1", 7)
            .is_ok());
        assert!(identity
            .validate_fields("durable_actor", "firecracker", "tenant-1", 7)
            .is_err());
        assert!(identity
            .validate_fields("phoenix", "firecracker", "tenant-2", 7)
            .is_err());
    }

    #[test]
    fn validates_identity_on_forwarded_frames() {
        let identity = GuestIdentity::from_cmdline(
            "bmscl.execution_class=durable_actor bmscl.execution_backend=firecracker \
             bmscl.tenant_id=t1 bmscl.runtime_epoch=9",
        )
        .unwrap();
        let good = serde_json::to_vec(&serde_json::json!({
            "op": "invoke",
            "execution_class": "durable_actor",
            "execution_backend": "firecracker",
            "tenant_id": "t1",
            "runtime_epoch": 9
        }))
        .unwrap();
        assert!(identity.validate_frame(&good).is_ok());

        let stale = serde_json::to_vec(&serde_json::json!({
            "op": "invoke",
            "execution_class": "durable_actor",
            "execution_backend": "firecracker",
            "tenant_id": "t1",
            "runtime_epoch": 8
        }))
        .unwrap();
        assert!(identity.validate_frame(&stale).is_err());
    }

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut a, mut b) = duplex(1024);
        let sender = tokio::spawn(async move { write_frame(&mut a, b"hello", 128).await.unwrap() });
        let bytes = read_frame(&mut b, 128).await.unwrap();
        sender.await.unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[tokio::test]
    async fn rejects_oversized_frame_before_allocating_payload() {
        let (mut a, mut b) = duplex(64);
        a.write_u32(4096).await.unwrap();
        let err = read_frame(&mut b, 128).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
