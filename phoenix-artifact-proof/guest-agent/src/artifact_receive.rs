use crate::{read_frame, write_frame};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{
    fs as async_fs,
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
};

const RECEIPT_FILE: &str = ".bmscl-transfer.json";
const MAX_PATH_BYTES: usize = 512;
const DEFAULT_MAX_FILES: usize = 4096;

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    BeamWorker,
    PhoenixRelease,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PutArtifactRequest {
    pub op: String,
    pub execution_class: String,
    pub execution_backend: String,
    pub tenant_id: String,
    pub runtime_epoch: u64,
    pub artifact_kind: ArtifactKind,
    pub build_sha256: String,
    pub archive_sha256: String,
    pub archive_name: String,
    pub archive_bytes: u64,
    pub chunk_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TransferReceipt {
    format_version: u32,
    artifact_kind: ArtifactKind,
    build_sha256: String,
    archive_sha256: String,
    archive_name: String,
    archive_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PutArtifactResponse {
    pub op: &'static str,
    pub ok: bool,
    pub build_sha256: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub state: &'static str,
}

pub fn decode_put_request(bytes: &[u8]) -> Result<Option<PutArtifactRequest>, String> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if value.get("op").and_then(serde_json::Value::as_str) != Some("put_artifact") {
        return Ok(None);
    }
    let request: PutArtifactRequest = serde_json::from_value(value)
        .map_err(|err| format!("invalid put_artifact request: {err}"))?;
    validate_request(&request)?;
    Ok(Some(request))
}

pub async fn receive_artifact<S>(
    stream: &mut S,
    request: PutArtifactRequest,
    artifact_root: &Path,
    max_archive_bytes: u64,
    max_extracted_bytes: u64,
    max_chunk_bytes: usize,
) -> Result<PutArtifactResponse, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    validate_request(&request)?;
    if request.archive_bytes > max_archive_bytes {
        return Err("artifact archive exceeds configured byte ceiling".into());
    }
    if request.chunk_bytes == 0 || request.chunk_bytes > max_chunk_bytes {
        return Err("artifact chunk size exceeds configured ceiling".into());
    }

    ensure_safe_root(artifact_root).map_err(|err| err.to_string())?;
    let final_dir = artifact_root.join(&request.build_sha256);
    if final_dir.exists() {
        validate_existing(&final_dir, &request)?;
        // The sender has already committed to transmitting archive_bytes after
        // the put_artifact header. Consume and verify the retry stream before
        // acknowledging it so leftover chunk frames cannot desynchronize a
        // reused transport or turn a tampered retry into a false success.
        consume_archive(stream, &request, max_chunk_bytes).await?;
        return Ok(success_response(&request, "already_present"));
    }

    let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    let staging = artifact_root.join(format!(
        ".incoming-{}-{}-{counter}",
        request.build_sha256,
        std::process::id()
    ));
    if staging.exists() {
        async_fs::remove_dir_all(&staging)
            .await
            .map_err(|err| format!("remove stale artifact staging directory: {err}"))?;
    }
    async_fs::create_dir(&staging)
        .await
        .map_err(|err| format!("create artifact staging directory: {err}"))?;

    let archive_path = staging.join(&request.archive_name);
    let receive_result = receive_archive(stream, &archive_path, &request, max_chunk_bytes).await;
    if let Err(err) = receive_result {
        let _ = async_fs::remove_dir_all(&staging).await;
        return Err(err);
    }

    let extract_path = archive_path.clone();
    let extract_dir = staging.clone();
    let archive_name = request.archive_name.clone();
    let extract_result = tokio::task::spawn_blocking(move || {
        extract_artifact(
            request.artifact_kind,
            &request.build_sha256,
            &archive_name,
            &extract_path,
            &extract_dir,
            max_extracted_bytes,
            DEFAULT_MAX_FILES,
        )
    })
    .await
    .map_err(|err| format!("artifact extraction task failed: {err}"))?;
    if let Err(err) = extract_result {
        let _ = async_fs::remove_dir_all(&staging).await;
        return Err(err);
    }

    let receipt = TransferReceipt {
        format_version: 2,
        artifact_kind: request.artifact_kind,
        build_sha256: request.build_sha256.clone(),
        archive_sha256: request.archive_sha256.clone(),
        archive_name: request.archive_name.clone(),
        archive_bytes: request.archive_bytes,
    };
    let receipt_bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|err| format!("serialize artifact transfer receipt: {err}"))?;
    async_fs::write(staging.join(RECEIPT_FILE), receipt_bytes)
        .await
        .map_err(|err| format!("write artifact transfer receipt: {err}"))?;

    match async_fs::rename(&staging, &final_dir).await {
        Ok(()) => Ok(success_response(&request, "stored")),
        Err(_) if final_dir.exists() => {
            let _ = async_fs::remove_dir_all(&staging).await;
            validate_existing(&final_dir, &request)?;
            Ok(success_response(&request, "already_present"))
        }
        Err(err) => {
            let _ = async_fs::remove_dir_all(&staging).await;
            Err(format!("commit immutable guest artifact: {err}"))
        }
    }
}

pub async fn write_error_response<S>(
    stream: &mut S,
    build_sha256: &str,
    message: impl Into<String>,
    max_frame_bytes: usize,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let bytes = serde_json::to_vec(&serde_json::json!({
        "op": "put_artifact_result",
        "ok": false,
        "build_sha256": build_sha256,
        "error": message.into()
    }))
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    write_frame(stream, &bytes, max_frame_bytes).await
}

pub async fn write_success_response<S>(
    stream: &mut S,
    response: &PutArtifactResponse,
    max_frame_bytes: usize,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let bytes = serde_json::to_vec(response)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    write_frame(stream, &bytes, max_frame_bytes).await
}

async fn receive_archive<S>(
    stream: &mut S,
    archive_path: &Path,
    request: &PutArtifactRequest,
    max_chunk_bytes: usize,
) -> Result<(), String>
where
    S: AsyncRead + Unpin,
{
    let mut file = async_fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(archive_path)
        .await
        .map_err(|err| format!("create incoming artifact archive: {err}"))?;
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    while received < request.archive_bytes {
        let chunk = read_artifact_chunk(stream, request, max_chunk_bytes, received).await?;
        let next = received + chunk.len() as u64;
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|err| format!("write incoming artifact chunk: {err}"))?;
        received = next;
    }
    file.flush()
        .await
        .map_err(|err| format!("flush incoming artifact archive: {err}"))?;
    validate_stream_digest(hasher, request)
}

async fn consume_archive<S>(
    stream: &mut S,
    request: &PutArtifactRequest,
    max_chunk_bytes: usize,
) -> Result<(), String>
where
    S: AsyncRead + Unpin,
{
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    while received < request.archive_bytes {
        let chunk = read_artifact_chunk(stream, request, max_chunk_bytes, received).await?;
        received += chunk.len() as u64;
        hasher.update(&chunk);
    }
    validate_stream_digest(hasher, request)
}

async fn read_artifact_chunk<S>(
    stream: &mut S,
    request: &PutArtifactRequest,
    max_chunk_bytes: usize,
    received: u64,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let chunk = read_frame(stream, max_chunk_bytes)
        .await
        .map_err(|err| format!("read artifact chunk: {err}"))?;
    if chunk.is_empty() {
        return Err("artifact stream contained a zero-length chunk".into());
    }
    let next = received
        .checked_add(chunk.len() as u64)
        .ok_or_else(|| "artifact byte counter overflow".to_string())?;
    if next > request.archive_bytes {
        return Err("artifact stream exceeded declared archive_bytes".into());
    }
    Ok(chunk)
}

fn validate_stream_digest(hasher: Sha256, request: &PutArtifactRequest) -> Result<(), String> {
    let actual = format!("{:x}", hasher.finalize());
    if actual != request.archive_sha256 {
        return Err("artifact archive digest mismatch inside guest".into());
    }
    Ok(())
}

fn validate_request(request: &PutArtifactRequest) -> Result<(), String> {
    if request.op != "put_artifact" {
        return Err("unsupported artifact operation".into());
    }
    validate_sha256(&request.build_sha256).map_err(|_| "invalid build_sha256".to_string())?;
    validate_sha256(&request.archive_sha256).map_err(|_| "invalid archive_sha256".to_string())?;
    match artifact_kind {
        ArtifactKind::BeamWorker
            if !matches!(request.archive_name.as_str(), "worker.zip" | "worker.tar.gz") =>
        {
            return Err("beam_worker archive_name must be worker.zip or worker.tar.gz".into());
        }
        ArtifactKind::PhoenixRelease if request.archive_name != "phoenix-release.tar.gz" => {
            return Err("phoenix_release archive_name must be phoenix-release.tar.gz".into());
        }
        _ => {}
    }
    if request.archive_bytes == 0 {
        return Err("archive_bytes must be positive".into());
    }
    if request.chunk_bytes == 0 {
        return Err("chunk_bytes must be positive".into());
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), ()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(())
    }
}

fn success_response(request: &PutArtifactRequest, state: &'static str) -> PutArtifactResponse {
    PutArtifactResponse {
        op: "put_artifact_result",
        ok: true,
        build_sha256: request.build_sha256.clone(),
        archive_sha256: request.archive_sha256.clone(),
        archive_bytes: request.archive_bytes,
        state,
    }
}

fn ensure_safe_root(root: &Path) -> io::Result<()> {
    fs::create_dir_all(root)?;
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest artifact root must be a real directory",
        ));
    }
    Ok(())
}

fn validate_existing(final_dir: &Path, request: &PutArtifactRequest) -> Result<(), String> {
    let metadata = fs::symlink_metadata(final_dir)
        .map_err(|err| format!("read existing artifact directory: {err}"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err("existing artifact path is not a real directory".into());
    }
    let receipt_bytes = fs::read(final_dir.join(RECEIPT_FILE))
        .map_err(|_| "existing artifact lacks a transfer receipt".to_string())?;
    let receipt: TransferReceipt = serde_json::from_slice(&receipt_bytes)
        .map_err(|_| "existing artifact has an invalid transfer receipt".to_string())?;
    let expected = TransferReceipt {
        format_version: 2,
        artifact_kind: request.artifact_kind,
        build_sha256: request.build_sha256.clone(),
        archive_sha256: request.archive_sha256.clone(),
        archive_name: request.archive_name.clone(),
        archive_bytes: request.archive_bytes,
    };
    if receipt != expected {
        return Err("existing artifact transfer receipt does not match request".into());
    }
    validate_extracted_artifact(final_dir, request.artifact_kind, &request.build_sha256)
}

fn extract_artifact(
    artifact_kind: ArtifactKind,
    expected_build_sha256: &str,
    archive_name: &str,
    archive_path: &Path,
    destination: &Path,
    max_extracted_bytes: u64,
    max_files: usize,
) -> Result<(), String> {
    match (artifact_kind, archive_name) {
        (ArtifactKind::BeamWorker, "worker.zip") => {
            extract_zip(
                artifact_kind,
                archive_path,
                destination,
                max_extracted_bytes,
                max_files,
            )?
        }
        (ArtifactKind::BeamWorker, "worker.tar.gz")
        | (ArtifactKind::PhoenixRelease, "phoenix-release.tar.gz") => {
            extract_tar_gz(
                artifact_kind,
                archive_path,
                destination,
                max_extracted_bytes,
                max_files,
            )?
        }
        _ => return Err("artifact kind and archive_name do not match".into()),
    }
    validate_extracted_artifact(destination, artifact_kind, expected_build_sha256)
}


fn extract_zip(
    artifact_kind: ArtifactKind,
    archive_path: &Path,
    destination: &Path,
    max_extracted_bytes: u64,
    max_files: usize,
) -> Result<(), String> {
    let file = File::open(archive_path).map_err(|err| format!("open ZIP artifact: {err}"))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|err| format!("open ZIP artifact: {err}"))?;
    let mut seen = HashSet::new();
    let mut total = 0u64;
    let mut files = 0usize;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|err| format!("read ZIP artifact entry: {err}"))?;
        let path = entry
            .enclosed_name()
            .ok_or_else(|| "ZIP artifact contains an unsafe path".to_string())?
            .to_path_buf();
        if entry.is_dir() {
            validate_directory_path(artifact_kind, &path)?;
            continue;
        }
        if !entry.is_file() {
            return Err("ZIP artifact may contain only regular files and beam/ directories".into());
        }
        if entry
            .unix_mode()
            .map(|mode| mode & 0o170000 == 0o120000)
            .unwrap_or(false)
        {
            return Err("ZIP artifact may not contain symlinks".into());
        }
        validate_artifact_path(artifact_kind, &path)?;
        if !seen.insert(path.clone()) {
            return Err(format!("duplicate artifact path {}", path.display()));
        }
        files = files
            .checked_add(1)
            .ok_or_else(|| "artifact file count overflow".to_string())?;
        if files > max_files {
            return Err("artifact contains too many files".into());
        }
        let size = entry.size();
        total = total
            .checked_add(size)
            .ok_or_else(|| "artifact extracted byte counter overflow".to_string())?;
        if total > max_extracted_bytes {
            return Err("artifact extracted bytes exceed configured ceiling".into());
        }
        let mode = entry.unix_mode().unwrap_or(0o644) & 0o777;
        validate_mode(artifact_kind, &path, mode)?;
        write_extracted_file(destination, &path, &mut entry, size, mode)?;
    }
    Ok(())
}

fn extract_tar_gz(
    artifact_kind: ArtifactKind,
    archive_path: &Path,
    destination: &Path,
    max_extracted_bytes: u64,
    max_files: usize,
) -> Result<(), String> {
    let file = File::open(archive_path).map_err(|err| format!("open tar.gz artifact: {err}"))?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut seen = HashSet::new();
    let mut total = 0u64;
    let mut files = 0usize;
    let entries = archive
        .entries()
        .map_err(|err| format!("read tar.gz artifact entries: {err}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|err| format!("read tar.gz artifact entry: {err}"))?;
        if !entry.header().entry_type().is_file() {
            return Err("tar.gz artifact may contain regular files only".into());
        }
        let path = entry
            .path()
            .map_err(|err| format!("read tar.gz artifact path: {err}"))?
            .into_owned();
        validate_artifact_path(artifact_kind, &path)?;
        if !seen.insert(path.clone()) {
            return Err(format!("duplicate artifact path {}", path.display()));
        }
        files = files
            .checked_add(1)
            .ok_or_else(|| "artifact file count overflow".to_string())?;
        if files > max_files {
            return Err("artifact contains too many files".into());
        }
        let size = entry.size();
        total = total
            .checked_add(size)
            .ok_or_else(|| "artifact extracted byte counter overflow".to_string())?;
        if total > max_extracted_bytes {
            return Err("artifact extracted bytes exceed configured ceiling".into());
        }
        let mode = entry.header().mode().map_err(|err| format!("read tar.gz artifact mode: {err}"))? & 0o7777;
        validate_mode(artifact_kind, &path, mode)?;
        write_extracted_file(destination, &path, &mut entry, size, mode)?;
    }
    Ok(())
}

fn write_extracted_file<R: Read>(
    destination: &Path,
    path: &Path,
    reader: &mut R,
    expected_bytes: u64,
    mode: u32,
) -> Result<(), String> {
    let output = destination.join(path);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create artifact directory {}: {err}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&output)
        .map_err(|err| format!("create extracted artifact {}: {err}", output.display()))?;
    let copied = io::copy(reader, &mut file)
        .map_err(|err| format!("extract artifact {}: {err}", output.display()))?;
    if copied != expected_bytes {
        return Err(format!(
            "artifact entry {} size changed during extraction",
            path.display()
        ));
    }
    file.flush()
        .map_err(|err| format!("flush artifact {}: {err}", output.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output, fs::Permissions::from_mode(mode & 0o777))
            .map_err(|err| format!("set artifact mode {}: {err}", output.display()))?;
    }
    Ok(())
}

fn validate_directory_path(
    artifact_kind: ArtifactKind,
    path: &Path,
) -> Result<(), String> {
    match artifact_kind {
        ArtifactKind::BeamWorker if path == Path::new("beam") => Ok(()),
        ArtifactKind::PhoenixRelease
            if path == Path::new("release") || path.starts_with("release/") =>
        {
            Ok(())
        }
        _ => Err(format!(
            "unexpected directory in deployment bundle: {}",
            path.display()
        )),
    }
}

fn validate_artifact_path(
    artifact_kind: ArtifactKind,
    path: &Path,
) -> Result<(), String> {
    if path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("invalid archive path {}", path.display()));
    }
    if matches!(
        path.to_str(),
        Some(
            "manifest.json"
                | "admission-report.json"
                | "provenance.json"
                | "attestation.json"
                | "admission-receipt.json"
        )
    ) {
        return Ok(());
    }

    match artifact_kind {
        ArtifactKind::BeamWorker => {
            let components: Vec<_> = path.components().collect();
            if components.len() == 2
                && components[0].as_os_str() == "beam"
                && path.extension().and_then(|ext| ext.to_str()) == Some("beam")
            {
                return Ok(());
            }
        }
        ArtifactKind::PhoenixRelease => {
            if path == Path::new("route-plan.json") {
                return Ok(());
            }
            let components: Vec<_> = path.components().collect();
            if components.len() >= 2 && components[0].as_os_str() == "release" {
                return Ok(());
            }
        }
    }
    Err(format!(
        "unexpected file in deployment bundle: {}",
        path.display()
    ))
}

fn validate_mode(
    artifact_kind: ArtifactKind,
    path: &Path,
    mode: u32,
) -> Result<(), String> {
    if mode & 0o6000 != 0 {
        return Err(format!(
            "setuid/setgid artifact mode is forbidden: {}",
            path.display()
        ));
    }
    if artifact_kind == ArtifactKind::BeamWorker && mode & 0o111 != 0 {
        return Err(format!(
            "BEAM worker files must not be executable: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_extracted_artifact(
    root: &Path,
    artifact_kind: ArtifactKind,
    expected_build_sha256: &str,
) -> Result<(), String> {
    for required in required_metadata_paths() {
        if !root.join(required).is_file() {
            return Err(format!("artifact archive is missing required {required}"));
        }
    }
    match request.artifact_kind {
        ArtifactKind::BeamWorker => {
            if !root.join("beam/worker.beam").is_file() {
                return Err("artifact archive is missing required beam/worker.beam".into());
            }
        }
        ArtifactKind::PhoenixRelease => validate_phoenix_release(root, expected_build_sha256)?,
    }
    Ok(())
}

fn validate_phoenix_release(root: &Path, expected_build: &str) -> Result<(), String> {
    let manifest_bytes =
        fs::read(root.join("manifest.json")).map_err(|err| format!("read Phoenix manifest: {err}"))?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|err| format!("parse Phoenix manifest: {err}"))?;
    for (field, expected) in [
        ("artifact_format", "bmscl-phoenix-release-v1"),
        ("artifact_root", "release"),
        ("runtime", "beam_release"),
        ("language", "elixir"),
        ("profile", "bmscl-phoenix-elixir-v1"),
        ("execution_class", "phoenix"),
        ("isolation_class", "firecracker"),
    ] {
        if manifest.get(field).and_then(serde_json::Value::as_str) != Some(expected) {
            return Err(format!("Phoenix manifest has invalid {field}"));
        }
    }
    if manifest.get("build_sha256").and_then(serde_json::Value::as_str)
        != Some(expected_build)
    {
        return Err("Phoenix manifest build_sha256 does not match transfer".into());
    }
    let app = manifest
        .get("app")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "Phoenix manifest is missing app".to_string())?;
    let version = manifest
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "Phoenix manifest is missing version".to_string())?;
    if !safe_segment(app) || !safe_version(version) {
        return Err("Phoenix manifest app/version is unsafe".into());
    }
    let route_digest = manifest
        .get("route_plan_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "Phoenix manifest is missing route_plan_sha256".to_string())?;
    validate_sha256(route_digest).map_err(|_| "invalid Phoenix route_plan_sha256".to_string())?;
    let route_bytes =
        fs::read(root.join("route-plan.json")).map_err(|_| "Phoenix route-plan.json missing".to_string())?;
    let actual_route = format!("{:x}", Sha256::digest(route_bytes));
    if actual_route != route_digest {
        return Err("Phoenix route-plan digest mismatch".into());
    }
    let bin = root.join("release/bin").join(app);
    let boot = root.join("release/releases").join(version).join("start.boot");
    if !bin.is_file() || !boot.is_file() {
        return Err("Phoenix release is missing bin/<app> or start.boot".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&bin)
            .map_err(|err| format!("inspect Phoenix launcher: {err}"))?
            .permissions()
            .mode();
        if mode & 0o111 == 0 || mode & 0o6000 != 0 {
            return Err("Phoenix release launcher must be executable without setuid/setgid".into());
        }
    }
    Ok(())
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn safe_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
}


fn required_metadata_paths() -> [&'static str; 5] {
    [
        "manifest.json",
        "admission-report.json",
        "provenance.json",
        "attestation.json",
        "admission-receipt.json",
    ]
}
