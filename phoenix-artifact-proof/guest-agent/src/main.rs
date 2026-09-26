use bmscl_guest_agent::{
    artifact_receive::{
        decode_put_request, receive_artifact, write_error_response, write_success_response,
    },
    read_frame, write_frame, GuestIdentity,
};
use std::{env, fs, io, path::PathBuf, sync::Arc};
use tokio::net::TcpStream;
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

struct ProxyConfig {
    supervisor_addr: String,
    artifact_root: PathBuf,
    guest_identity: GuestIdentity,
    max_frame_bytes: usize,
    max_artifact_bytes: u64,
    max_extracted_bytes: u64,
    max_chunk_bytes: usize,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let boot_cmdline = match env::var("BMSCL_GUEST_BOOT_CMDLINE") {
        Ok(value) => value,
        Err(_) => fs::read_to_string("/proc/cmdline")?,
    };
    let guest_identity = GuestIdentity::from_cmdline(&boot_cmdline)?;

    let vsock_port = env::var("BMSCL_GUEST_VSOCK_PORT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(5000);
    let supervisor_addr =
        env::var("BMSCL_GUEST_SUPERVISOR_ADDR").unwrap_or_else(|_| "127.0.0.1:9101".into());
    let max_frame_bytes = env::var("BMSCL_GUEST_MAX_FRAME_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(16 * 1024 * 1024);
    let artifact_root = env::var_os("BMSCL_GUEST_ARTIFACT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/beamscale/artifacts"));
    let max_artifact_bytes = env::var("BMSCL_MAX_ARTIFACT_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(64 * 1024 * 1024);
    let max_extracted_bytes = env::var("BMSCL_GUEST_MAX_EXTRACTED_ARTIFACT_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(256 * 1024 * 1024);
    let max_chunk_bytes = env::var("BMSCL_GUEST_MAX_ARTIFACT_CHUNK_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1024 * 1024)
        .min(max_frame_bytes);

    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port))?;
    let proxy_config = Arc::new(ProxyConfig {
        supervisor_addr,
        artifact_root,
        guest_identity,
        max_frame_bytes,
        max_artifact_bytes,
        max_extracted_bytes,
        max_chunk_bytes,
    });

    tracing::info!(
        vsock_port,
        supervisor_addr = %proxy_config.supervisor_addr,
        artifact_root = %proxy_config.artifact_root.display(),
        max_artifact_bytes = proxy_config.max_artifact_bytes,
        max_extracted_bytes = proxy_config.max_extracted_bytes,
        max_chunk_bytes = proxy_config.max_chunk_bytes,
        execution_class = %proxy_config.guest_identity.execution_class,
        execution_backend = %proxy_config.guest_identity.execution_backend,
        tenant_id = %proxy_config.guest_identity.tenant_id,
        runtime_epoch = proxy_config.guest_identity.runtime_epoch,
        "BeamScale guest agent listening"
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let proxy_config = Arc::clone(&proxy_config);
        tokio::spawn(async move {
            if let Err(err) = proxy_once(stream, &proxy_config).await {
                tracing::warn!(
                    peer_cid = peer.cid(),
                    peer_port = peer.port(),
                    error = %err,
                    "guest vsock request failed"
                );
            }
        });
    }
}

async fn proxy_once(mut vsock: tokio_vsock::VsockStream, config: &ProxyConfig) -> io::Result<()> {
    let request = read_frame(&mut vsock, config.max_frame_bytes).await?;
    match decode_put_request(&request) {
        Ok(Some(put)) => {
            let build_sha256 = put.build_sha256.clone();
            if let Err(message) = config.guest_identity.validate_fields(
                &put.execution_class,
                &put.execution_backend,
                &put.tenant_id,
                put.runtime_epoch,
            ) {
                tracing::warn!(%build_sha256, error = %message, "guest artifact identity rejected");
                return write_error_response(
                    &mut vsock,
                    &build_sha256,
                    message,
                    config.max_frame_bytes,
                )
                .await;
            }
            match receive_artifact(
                &mut vsock,
                put,
                &config.artifact_root,
                config.max_artifact_bytes,
                config.max_extracted_bytes,
                config.max_chunk_bytes,
            )
            .await
            {
                Ok(response) => {
                    write_success_response(&mut vsock, &response, config.max_frame_bytes).await
                }
                Err(message) => {
                    tracing::warn!(%build_sha256, error = %message, "guest artifact transfer rejected");
                    write_error_response(&mut vsock, &build_sha256, message, config.max_frame_bytes)
                        .await
                }
            }
        }
        Err(message) => {
            tracing::warn!(error = %message, "invalid guest artifact transfer header");
            write_error_response(&mut vsock, "", message, config.max_frame_bytes).await
        }
        Ok(None) => {
            if let Err(message) = config.guest_identity.validate_frame(&request) {
                tracing::warn!(error = %message, "guest request identity rejected");
                let response = serde_json::to_vec(&serde_json::json!({
                    "op": "identity_rejected",
                    "ok": false,
                    "error": message
                }))
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                return write_frame(&mut vsock, &response, config.max_frame_bytes).await;
            }
            let mut supervisor = TcpStream::connect(&config.supervisor_addr).await?;
            write_frame(&mut supervisor, &request, config.max_frame_bytes).await?;
            let response = read_frame(&mut supervisor, config.max_frame_bytes).await?;
            write_frame(&mut vsock, &response, config.max_frame_bytes).await
        }
    }
}
