use flate2::{write::GzEncoder, Compression, GzBuilder};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    io,
    path::{Path, PathBuf},
};
use tar::{Builder, Header};
use thiserror::Error;
use tokio::{fs, io::AsyncReadExt};

const ADMITTED_METADATA: [&str; 5] = [
    "manifest.json",
    "admission-report.json",
    "provenance.json",
    "attestation.json",
    "admission-receipt.json",
];
const REQUIRED_WORKER_BEAM: &str = "beam/worker.beam";

#[derive(Clone, Debug)]
pub struct ArtifactStore {
    root: PathBuf,
    max_archive_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedArtifact {
    pub build_sha256: String,
    pub archive_name: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub archive_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedArtifact {
    pub build_sha256: String,
    pub archive_name: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct DeploymentRecord {
    build_sha256: String,
    archive_sha256: String,
    archive_name: String,
    archive_bytes: u64,
    verification_state: String,
}

#[derive(Debug, Error)]
pub enum ArtifactStoreError {
    #[error("invalid build sha256")]
    InvalidDigest,
    #[error("artifact not found")]
    NotFound,
    #[error("artifact registry entry is not a real directory")]
    UnsafeRegistryEntry,
    #[error("artifact archive is not a real file")]
    UnsafeArchive,
    #[error("artifact registry escaped configured root")]
    RegistryEscape,
    #[error("unsafe admitted artifact member: {0}")]
    UnsafeAdmittedMember(String),
    #[error("invalid deployment record: {0}")]
    InvalidRecord(String),
    #[error("artifact archive exceeds configured byte ceiling")]
    ArchiveTooLarge,
    #[error("artifact archive digest mismatch")]
    ArchiveDigestMismatch,
    #[error("artifact io error: {0}")]
    Io(#[from] io::Error),
    #[error("artifact record json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl ArtifactStore {
    pub fn new(root: impl Into<PathBuf>, max_archive_bytes: u64) -> Self {
        Self {
            root: root.into(),
            max_archive_bytes,
        }
    }

    pub async fn resolve(
        &self,
        build_sha256: &str,
    ) -> Result<ResolvedArtifact, ArtifactStoreError> {
        validate_sha256(build_sha256)?;
        let (root, canonical_dir, record) = self.resolve_directory(build_sha256).await?;

        let archive_path = canonical_dir.join(&record.archive_name);
        let archive_meta = fs::symlink_metadata(&archive_path)
            .await
            .map_err(map_not_found)?;
        if !archive_meta.file_type().is_file() || archive_meta.file_type().is_symlink() {
            return Err(ArtifactStoreError::UnsafeArchive);
        }
        let canonical_archive = fs::canonicalize(&archive_path).await?;
        if !canonical_archive.starts_with(&canonical_dir) || !canonical_archive.starts_with(&root) {
            return Err(ArtifactStoreError::RegistryEscape);
        }
        if archive_meta.len() == 0
            || archive_meta.len() > self.max_archive_bytes
            || archive_meta.len() != record.archive_bytes
        {
            return Err(ArtifactStoreError::ArchiveTooLarge);
        }

        let actual_sha256 = hash_file(&canonical_archive, self.max_archive_bytes).await?;
        if actual_sha256 != record.archive_sha256 {
            return Err(ArtifactStoreError::ArchiveDigestMismatch);
        }

        Ok(ResolvedArtifact {
            build_sha256: record.build_sha256,
            archive_name: record.archive_name,
            archive_sha256: actual_sha256,
            archive_bytes: archive_meta.len(),
            archive_path: canonical_archive,
        })
    }

    pub async fn resolve_admitted_bundle(
        &self,
        build_sha256: &str,
    ) -> Result<AdmittedArtifact, ArtifactStoreError> {
        self.resolve(build_sha256).await?;
        let (_root, canonical_dir, _record) = self.resolve_directory(build_sha256).await?;

        let mut entries = Vec::<(String, Vec<u8>)>::new();
        let mut total_uncompressed = 0u64;
        for name in ADMITTED_METADATA {
            let bytes = read_regular_member(
                &canonical_dir,
                &canonical_dir.join(name),
                name,
                self.max_archive_bytes,
                &mut total_uncompressed,
            )
            .await?;
            entries.push((name.to_owned(), bytes));
        }

        let beam_dir = canonical_dir.join("beam");
        let beam_meta = fs::symlink_metadata(&beam_dir)
            .await
            .map_err(map_not_found)?;
        if !beam_meta.file_type().is_dir() || beam_meta.file_type().is_symlink() {
            return Err(ArtifactStoreError::UnsafeAdmittedMember("beam".into()));
        }
        let canonical_beam = fs::canonicalize(&beam_dir).await?;
        if !canonical_beam.starts_with(&canonical_dir) || canonical_beam == canonical_dir {
            return Err(ArtifactStoreError::RegistryEscape);
        }

        let mut reader = fs::read_dir(&canonical_beam).await?;
        while let Some(entry) = reader.next_entry().await? {
            let file_name = entry.file_name().into_string().map_err(|_| {
                ArtifactStoreError::UnsafeAdmittedMember("non-utf8 beam file".into())
            })?;
            if file_name.is_empty()
                || !file_name.ends_with(".beam")
                || file_name.contains('/')
                || file_name.contains('\\')
            {
                return Err(ArtifactStoreError::UnsafeAdmittedMember(format!(
                    "beam/{file_name}"
                )));
            }
            let relative = format!("beam/{file_name}");
            let bytes = read_regular_member(
                &canonical_dir,
                &entry.path(),
                &relative,
                self.max_archive_bytes,
                &mut total_uncompressed,
            )
            .await?;
            entries.push((relative, bytes));
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        if !entries.iter().any(|(name, _)| name == REQUIRED_WORKER_BEAM) {
            return Err(ArtifactStoreError::InvalidRecord(
                "admitted artifact is missing beam/worker.beam".into(),
            ));
        }

        let archive = tokio::task::spawn_blocking(move || build_admitted_tar_gz(entries))
            .await
            .map_err(|err| {
                ArtifactStoreError::InvalidRecord(format!(
                    "admitted artifact packaging task failed: {err}"
                ))
            })??;
        let archive_bytes = archive.len() as u64;
        if archive_bytes == 0 || archive_bytes > self.max_archive_bytes {
            return Err(ArtifactStoreError::ArchiveTooLarge);
        }
        let archive_sha256 = format!("{:x}", Sha256::digest(&archive));

        Ok(AdmittedArtifact {
            build_sha256: build_sha256.to_owned(),
            archive_name: "worker.tar.gz".into(),
            archive_sha256,
            archive_bytes,
            bytes: archive,
        })
    }

    async fn resolve_directory(
        &self,
        build_sha256: &str,
    ) -> Result<(PathBuf, PathBuf, DeploymentRecord), ArtifactStoreError> {
        validate_sha256(build_sha256)?;
        let root = fs::canonicalize(&self.root).await.map_err(map_not_found)?;
        let deployment_dir = self.root.join(build_sha256);
        let dir_meta = fs::symlink_metadata(&deployment_dir)
            .await
            .map_err(map_not_found)?;
        if !dir_meta.file_type().is_dir() || dir_meta.file_type().is_symlink() {
            return Err(ArtifactStoreError::UnsafeRegistryEntry);
        }
        let canonical_dir = fs::canonicalize(&deployment_dir).await?;
        if !canonical_dir.starts_with(&root) || canonical_dir == root {
            return Err(ArtifactStoreError::RegistryEscape);
        }

        let record_bytes = fs::read(canonical_dir.join(".deployment.json"))
            .await
            .map_err(map_not_found)?;
        let record: DeploymentRecord = serde_json::from_slice(&record_bytes)?;
        validate_record(build_sha256, &record, self.max_archive_bytes)?;
        Ok((root, canonical_dir, record))
    }
}

async fn read_regular_member(
    deployment_dir: &Path,
    path: &Path,
    relative: &str,
    max_bytes: u64,
    total: &mut u64,
) -> Result<Vec<u8>, ArtifactStoreError> {
    let meta = fs::symlink_metadata(path).await.map_err(map_not_found)?;
    if !meta.file_type().is_file() || meta.file_type().is_symlink() {
        return Err(ArtifactStoreError::UnsafeAdmittedMember(relative.into()));
    }
    let canonical = fs::canonicalize(path).await?;
    if !canonical.starts_with(deployment_dir) || canonical == deployment_dir {
        return Err(ArtifactStoreError::RegistryEscape);
    }
    *total = total
        .checked_add(meta.len())
        .ok_or(ArtifactStoreError::ArchiveTooLarge)?;
    if *total > max_bytes {
        return Err(ArtifactStoreError::ArchiveTooLarge);
    }
    let bytes = fs::read(&canonical).await?;
    if bytes.len() as u64 != meta.len() {
        return Err(ArtifactStoreError::UnsafeAdmittedMember(format!(
            "{relative} changed while packaging"
        )));
    }
    Ok(bytes)
}

fn build_admitted_tar_gz(entries: Vec<(String, Vec<u8>)>) -> Result<Vec<u8>, ArtifactStoreError> {
    let encoder: GzEncoder<Vec<u8>> = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    for (path, bytes) in entries {
        let mut header = Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive.append_data(&mut header, path, bytes.as_slice())?;
    }
    let encoder = archive.into_inner()?;
    Ok(encoder.finish()?)
}

fn validate_record(
    requested_digest: &str,
    record: &DeploymentRecord,
    max_archive_bytes: u64,
) -> Result<(), ArtifactStoreError> {
    validate_sha256(&record.build_sha256)?;
    validate_sha256(&record.archive_sha256)?;
    if record.build_sha256 != requested_digest {
        return Err(ArtifactStoreError::InvalidRecord(
            "registry key does not match build_sha256".into(),
        ));
    }
    if record.verification_state != "verified" {
        return Err(ArtifactStoreError::InvalidRecord(
            "artifact is not in verified state".into(),
        ));
    }
    if !matches!(record.archive_name.as_str(), "worker.zip" | "worker.tar.gz") {
        return Err(ArtifactStoreError::InvalidRecord(
            "archive_name is not canonical".into(),
        ));
    }
    if record.archive_bytes == 0 || record.archive_bytes > max_archive_bytes {
        return Err(ArtifactStoreError::ArchiveTooLarge);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), ArtifactStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ArtifactStoreError::InvalidDigest)
    }
}

async fn hash_file(path: &Path, max_bytes: u64) -> Result<String, ArtifactStoreError> {
    let mut file = fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(ArtifactStoreError::ArchiveTooLarge)?;
        if total > max_bytes {
            return Err(ArtifactStoreError::ArchiveTooLarge);
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn map_not_found(error: io::Error) -> ArtifactStoreError {
    if error.kind() == io::ErrorKind::NotFound {
        ArtifactStoreError::NotFound
    } else {
        ArtifactStoreError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::fs as stdfs;
    use tempfile::TempDir;

    fn digest(byte: u8) -> String {
        format!("{:064x}", byte)
    }

    fn archive_digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn write_fixture(root: &Path, build: &str, archive: &[u8]) {
        let dir = root.join(build);
        stdfs::create_dir_all(dir.join("beam")).unwrap();
        let archive_sha256 = archive_digest(archive);
        stdfs::write(dir.join("worker.zip"), archive).unwrap();
        for (name, bytes) in [
            ("manifest.json", b"manifest".as_slice()),
            ("admission-report.json", b"report".as_slice()),
            ("provenance.json", b"provenance".as_slice()),
            ("attestation.json", b"attestation".as_slice()),
            ("admission-receipt.json", b"receipt".as_slice()),
        ] {
            stdfs::write(dir.join(name), bytes).unwrap();
        }
        stdfs::write(dir.join("beam/worker.beam"), b"FOR1worker").unwrap();
        stdfs::write(dir.join("beam/helper.beam"), b"FOR1helper").unwrap();
        let record = serde_json::json!({
            "build_sha256": build,
            "source_sha256": digest(9),
            "runtime": "beam",
            "language": "gleam",
            "profile": "bmscl-hosted-gleam-v1",
            "key_id": "test",
            "archive_sha256": archive_sha256,
            "archive_name": "worker.zip",
            "archive_bytes": archive.len(),
            "accepted_unix_seconds": 1,
            "verification_state": "verified",
            "activation_state": "not-connected"
        });
        stdfs::write(
            dir.join(".deployment.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn resolves_only_verified_digest_keyed_archives() {
        let tmp = TempDir::new().unwrap();
        let build = digest(1);
        write_fixture(tmp.path(), &build, b"zip-fixture");
        let store = ArtifactStore::new(tmp.path(), 1024);
        let resolved = store.resolve(&build).await.unwrap();
        assert_eq!(resolved.build_sha256, build);
        assert_eq!(resolved.archive_name, "worker.zip");
        assert_eq!(resolved.archive_bytes, 11);
    }

    #[tokio::test]
    async fn materializes_receipt_bearing_admitted_bundle_deterministically() {
        let tmp = TempDir::new().unwrap();
        let build = digest(7);
        write_fixture(tmp.path(), &build, b"zip-fixture");
        let store = ArtifactStore::new(tmp.path(), 1024 * 1024);
        let first = store.resolve_admitted_bundle(&build).await.unwrap();
        let second = store.resolve_admitted_bundle(&build).await.unwrap();
        assert_eq!(first.archive_name, "worker.tar.gz");
        assert_eq!(first.archive_sha256, second.archive_sha256);
        assert_eq!(first.bytes, second.bytes);

        let decoder = GzDecoder::new(first.bytes.as_slice());
        let mut archive = tar::Archive::new(decoder);
        let names = archive
            .entries()
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        assert!(names.contains(&"admission-receipt.json".into()));
        assert!(names.contains(&"beam/worker.beam".into()));
        assert!(names.contains(&"beam/helper.beam".into()));
    }

    #[tokio::test]
    async fn admitted_bundle_fails_closed_without_receipt() {
        let tmp = TempDir::new().unwrap();
        let build = digest(8);
        write_fixture(tmp.path(), &build, b"zip-fixture");
        stdfs::remove_file(tmp.path().join(&build).join("admission-receipt.json")).unwrap();
        let store = ArtifactStore::new(tmp.path(), 1024 * 1024);
        assert!(matches!(
            store.resolve_admitted_bundle(&build).await,
            Err(ArtifactStoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn rejects_digest_mismatch_and_oversized_archives() {
        let tmp = TempDir::new().unwrap();
        let build = digest(2);
        write_fixture(tmp.path(), &build, b"too-large");
        let store = ArtifactStore::new(tmp.path(), 4);
        assert!(matches!(
            store.resolve(&build).await,
            Err(ArtifactStoreError::ArchiveTooLarge)
        ));
        assert!(matches!(
            store.resolve("../../escape").await,
            Err(ArtifactStoreError::InvalidDigest)
        ));
    }

    #[tokio::test]
    async fn rejects_tampered_archive_and_registry_symlink() {
        let tmp = TempDir::new().unwrap();
        let build = digest(3);
        write_fixture(tmp.path(), &build, b"original");
        stdfs::write(tmp.path().join(&build).join("worker.zip"), b"tampered").unwrap();
        let store = ArtifactStore::new(tmp.path(), 1024);
        assert!(matches!(
            store.resolve(&build).await,
            Err(ArtifactStoreError::ArchiveDigestMismatch)
        ));

        #[cfg(unix)]
        {
            let build2 = digest(4);
            std::os::unix::fs::symlink(tmp.path().join(&build), tmp.path().join(&build2)).unwrap();
            assert!(matches!(
                store.resolve(&build2).await,
                Err(ArtifactStoreError::UnsafeRegistryEntry)
            ));
        }
    }
}
