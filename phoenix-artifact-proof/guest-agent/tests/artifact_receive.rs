use bmscl_guest_agent::{
    artifact_receive::{ArtifactKind, receive_artifact, PutArtifactRequest},
    read_frame, write_frame,
};
use flate2::{Compression, GzBuilder};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};
use tar::{Builder, Header};
use tempfile::TempDir;
use tokio::io::{duplex, AsyncWriteExt};
use zip::{write::SimpleFileOptions, ZipWriter};

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn build_digest(byte: u8) -> String {
    format!("{:064x}", byte)
}

fn valid_zip(extra: Option<(&str, &[u8])>) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default();
    for (path, bytes) in [
        ("manifest.json", br#"{"build_sha256":"fixture"}"#.as_slice()),
        ("admission-report.json", br#"{"admitted":true}"#.as_slice()),
        ("provenance.json", br#"{"format":"fixture"}"#.as_slice()),
        ("attestation.json", br#"{"format":"fixture"}"#.as_slice()),
        (
            "admission-receipt.json",
            br#"{"format":"bmscl-admission-receipt-v1"}"#.as_slice(),
        ),
        ("beam/worker.beam", b"FOR1fixture".as_slice()),
    ] {
        writer.start_file(path, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    if let Some((path, bytes)) = extra {
        writer.start_file(path, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn zip_without_receipt() -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default();
    for (path, bytes) in [
        ("manifest.json", b"manifest".as_slice()),
        ("admission-report.json", b"report".as_slice()),
        ("provenance.json", b"provenance".as_slice()),
        ("attestation.json", b"attestation".as_slice()),
        ("beam/worker.beam", b"FOR1fixture".as_slice()),
    ] {
        writer.start_file(path, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn request(build: String, archive: &[u8], archive_sha256: String) -> PutArtifactRequest {
    PutArtifactRequest {
        op: "put_artifact".into(),
        execution_class: "phoenix".into(),
        execution_backend: "firecracker".into(),
        tenant_id: "tenant-test".into(),
        runtime_epoch: 1,
        artifact_kind: ArtifactKind::BeamWorker,
        build_sha256: build,
        archive_sha256,
        archive_name: "worker.zip".into(),
        archive_bytes: archive.len() as u64,
        chunk_bytes: 97,
    }
}

fn append_tar_file(
    archive: &mut Builder<flate2::write::GzEncoder<Vec<u8>>>,
    path: &str,
    bytes: &[u8],
    mode: u32,
) {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    archive.append_data(&mut header, path, bytes).unwrap();
}

fn phoenix_tar(build: &str, tamper_route: bool, extra: Option<(&str, &[u8])>) -> Vec<u8> {
    let route = if tamper_route { br#"{"tampered":true}"#.as_slice() } else { br#"{"ok":true}"#.as_slice() };
    let route_sha = digest(if tamper_route { br#"{"ok":true}"# } else { route });
    let manifest = serde_json::to_vec(&serde_json::json!({
        "format_version": 1,
        "artifact_format": "bmscl-phoenix-release-v1",
        "artifact_root": "release",
        "runtime": "beam_release",
        "language": "elixir",
        "profile": "bmscl-phoenix-elixir-v1",
        "execution_class": "phoenix",
        "isolation_class": "firecracker",
        "source_sha256": build_digest(9),
        "build_sha256": build,
        "provenance_sha256": build_digest(8),
        "app": "demo",
        "version": "1.2.3",
        "router": "DemoWeb.Router",
        "endpoint": "DemoWeb.Endpoint",
        "route_plan_sha256": route_sha
    }))
    .unwrap();

    let encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    for (path, bytes, mode) in [
        ("manifest.json", manifest.as_slice(), 0o644),
        ("admission-report.json", b"{}".as_slice(), 0o644),
        ("provenance.json", b"{}".as_slice(), 0o644),
        ("attestation.json", b"{}".as_slice(), 0o644),
        ("admission-receipt.json", b"{}".as_slice(), 0o644),
        ("route-plan.json", route, 0o644),
        ("release/bin/demo", b"#!/bin/sh\n".as_slice(), 0o755),
        ("release/releases/1.2.3/start.boot", b"boot".as_slice(), 0o644),
        ("release/lib/demo-1.2.3/ebin/demo.beam", b"FOR1demo".as_slice(), 0o644),
    ] {
        append_tar_file(&mut archive, path, bytes, mode);
    }
    if let Some((path, bytes)) = extra {
        append_tar_file(&mut archive, path, bytes, 0o644);
    }
    let encoder = archive.into_inner().unwrap();
    encoder.finish().unwrap()
}

fn phoenix_request(build: String, archive: &[u8]) -> PutArtifactRequest {
    PutArtifactRequest {
        op: "put_artifact".into(),
        execution_class: "phoenix".into(),
        execution_backend: "firecracker".into(),
        tenant_id: "tenant-test".into(),
        runtime_epoch: 1,
        artifact_kind: ArtifactKind::PhoenixRelease,
        build_sha256: build,
        archive_sha256: digest(archive),
        archive_name: "phoenix-release.tar.gz".into(),
        archive_bytes: archive.len() as u64,
        chunk_bytes: 97,
    }
}

async fn stream_archive(
    archive: Vec<u8>,
    request: PutArtifactRequest,
    root: &std::path::Path,
) -> Result<bmscl_guest_agent::artifact_receive::PutArtifactResponse, String> {
    let capacity = archive.len() + 4096;
    let (mut writer, mut reader) = duplex(capacity);
    let sender_request = request.clone();
    let sender = tokio::spawn(async move {
        for chunk in archive.chunks(sender_request.chunk_bytes) {
            write_frame(&mut writer, chunk, sender_request.chunk_bytes)
                .await
                .unwrap();
        }
    });
    let response = receive_artifact(
        &mut reader,
        request,
        root,
        8 * 1024 * 1024,
        32 * 1024 * 1024,
        1024,
    )
    .await;
    sender.await.unwrap();
    response
}

#[tokio::test]
async fn zero_length_frame_is_rejected_before_artifact_progress() {
    let (mut writer, mut reader) = duplex(64);
    writer.write_u32(0).await.unwrap();
    let err = read_frame(&mut reader, 1024).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("invalid frame length 0"));
}

#[tokio::test]
async fn streams_hashes_extracts_receipt_and_commits_atomically() {
    let root = TempDir::new().unwrap();
    let archive = valid_zip(None);
    let build = build_digest(1);
    let response = stream_archive(
        archive.clone(),
        request(build.clone(), &archive, digest(&archive)),
        root.path(),
    )
    .await
    .unwrap();

    assert!(response.ok);
    assert_eq!(response.state, "stored");
    let deployed = root.path().join(&build);
    assert!(deployed.join("manifest.json").is_file());
    assert!(deployed.join("admission-report.json").is_file());
    assert!(deployed.join("provenance.json").is_file());
    assert!(deployed.join("attestation.json").is_file());
    assert!(deployed.join("admission-receipt.json").is_file());
    assert!(deployed.join("beam/worker.beam").is_file());
    assert!(deployed.join("worker.zip").is_file());
    assert!(deployed.join(".bmscl-transfer.json").is_file());
}

#[tokio::test]
async fn repeated_identical_transfer_consumes_and_verifies_retry_stream() {
    let root = TempDir::new().unwrap();
    let archive = valid_zip(None);
    let build = build_digest(2);
    let req = request(build.clone(), &archive, digest(&archive));
    stream_archive(archive.clone(), req.clone(), root.path())
        .await
        .unwrap();

    let response = stream_archive(archive.clone(), req, root.path())
        .await
        .unwrap();
    assert_eq!(response.state, "already_present");
}

#[tokio::test]
async fn repeated_transfer_rejects_tampered_retry_bytes() {
    let root = TempDir::new().unwrap();
    let archive = valid_zip(None);
    let build = build_digest(9);
    let req = request(build.clone(), &archive, digest(&archive));
    stream_archive(archive.clone(), req.clone(), root.path())
        .await
        .unwrap();

    let mut tampered = archive.clone();
    tampered[0] ^= 1;
    let err = stream_archive(tampered, req, root.path())
        .await
        .unwrap_err();
    assert!(err.contains("digest mismatch"));
}

#[tokio::test]
async fn digest_mismatch_is_rejected_and_staging_is_removed() {
    let root = TempDir::new().unwrap();
    let archive = valid_zip(None);
    let build = build_digest(3);
    let err = stream_archive(
        archive.clone(),
        request(build.clone(), &archive, build_digest(9)),
        root.path(),
    )
    .await
    .unwrap_err();
    assert!(err.contains("digest mismatch"));
    assert!(!root.path().join(build).exists());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn missing_admission_receipt_is_rejected() {
    let root = TempDir::new().unwrap();
    let archive = zip_without_receipt();
    let build = build_digest(6);
    let err = stream_archive(
        archive.clone(),
        request(build.clone(), &archive, digest(&archive)),
        root.path(),
    )
    .await
    .unwrap_err();
    assert!(err.contains("missing required admission-receipt.json"));
    assert!(!root.path().join(build).exists());
}

#[tokio::test]
async fn unexpected_archive_paths_are_rejected() {
    let root = TempDir::new().unwrap();
    let archive = valid_zip(Some(("secrets.txt", b"nope")));
    let build = build_digest(4);
    let err = stream_archive(
        archive.clone(),
        request(build.clone(), &archive, digest(&archive)),
        root.path(),
    )
    .await
    .unwrap_err();
    assert!(err.contains("unexpected file"));
    assert!(!root.path().join(build).exists());
}

#[tokio::test]
async fn phoenix_release_preserves_executable_launcher_and_commits_atomically() {
    let root = TempDir::new().unwrap();
    let build = build_digest(7);
    let archive = phoenix_tar(&build, false, None);
    let response = stream_archive(
        archive.clone(),
        phoenix_request(build.clone(), &archive),
        root.path(),
    )
    .await
    .unwrap();
    assert_eq!(response.state, "stored");
    let deployed = root.path().join(&build);
    assert!(deployed.join("route-plan.json").is_file());
    assert!(deployed.join("release/releases/1.2.3/start.boot").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(deployed.join("release/bin/demo"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0);
        assert_eq!(mode & 0o6000, 0);
    }
}

#[tokio::test]
async fn phoenix_release_rejects_route_plan_tampering() {
    let root = TempDir::new().unwrap();
    let build = build_digest(8);
    let archive = phoenix_tar(&build, true, None);
    let err = stream_archive(
        archive.clone(),
        phoenix_request(build.clone(), &archive),
        root.path(),
    )
    .await
    .unwrap_err();
    assert!(err.contains("route-plan digest mismatch"));
    assert!(!root.path().join(build).exists());
}

#[tokio::test]
async fn phoenix_release_rejects_files_outside_release_root() {
    let root = TempDir::new().unwrap();
    let build = build_digest(10);
    let archive = phoenix_tar(&build, false, Some(("secrets.txt", b"nope")));
    let err = stream_archive(
        archive.clone(),
        phoenix_request(build.clone(), &archive),
        root.path(),
    )
    .await
    .unwrap_err();
    assert!(err.contains("unexpected file"));
    assert!(!root.path().join(build).exists());
}

#[tokio::test]
async fn artifact_kind_is_bound_to_archive_name() {
    let root = TempDir::new().unwrap();
    let build = build_digest(11);
    let archive = phoenix_tar(&build, false, None);
    let mut req = phoenix_request(build, &archive);
    req.archive_name = "worker.tar.gz".into();
    let err = stream_archive(archive, req, root.path()).await.unwrap_err();
    assert!(err.contains("phoenix_release archive_name"));
}

#[tokio::test]
async fn declared_archive_ceiling_is_enforced_before_streaming() {
    let root = TempDir::new().unwrap();
    let archive = valid_zip(None);
    let req = request(build_digest(5), &archive, digest(&archive));
    let (_writer, mut reader) = duplex(64);
    let err = receive_artifact(&mut reader, req, root.path(), 1, 32 * 1024 * 1024, 1024)
        .await
        .unwrap_err();
    assert!(err.contains("byte ceiling"));
}
