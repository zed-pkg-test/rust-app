use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use std::{
    collections::BTreeSet,
    fs,
    io::{Cursor, Read, Write},
    path::{Component, Path, PathBuf},
};

const MAX_ARCHIVE_FILES: usize = 4096;
const MAX_COMPRESSION_RATIO: u64 = 256;
const MIN_RATIO_CHECK_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ArchiveLimits {
    pub(crate) max_expanded_bytes: usize,
    pub(crate) max_file_bytes: usize,
    pub(crate) max_files: usize,
}

impl ArchiveLimits {
    pub(crate) fn for_upload_ceiling(max_upload_bytes: usize) -> Self {
        Self {
            max_expanded_bytes: max_upload_bytes,
            max_file_bytes: max_upload_bytes,
            max_files: MAX_ARCHIVE_FILES,
        }
    }
}

#[derive(Default)]
struct ExtractionState {
    paths: BTreeSet<PathBuf>,
    files: usize,
    expanded_bytes: usize,
}

pub(crate) fn extract_artifact(
    filename: &str,
    bytes: &[u8],
    destination: &Path,
    limits: ArchiveLimits,
) -> Result<()> {
    if limits.max_expanded_bytes == 0 || limits.max_file_bytes == 0 || limits.max_files == 0 {
        bail!("archive extraction limits must be positive");
    }

    if bytes.starts_with(b"PK\x03\x04") || filename.ends_with(".zip") {
        extract_zip(bytes, destination, limits)?;
    } else if bytes.starts_with(&[0x1f, 0x8b])
        || filename.ends_with(".tar.gz")
        || filename.ends_with(".tgz")
    {
        extract_tar_gz(bytes, destination, limits)?;
    } else {
        bail!("expected a .zip or .tar.gz BeamScale bundle");
    }

    for required in [
        "manifest.json",
        "admission-report.json",
        "provenance.json",
        "attestation.json",
    ] {
        if !destination.join(required).is_file() {
            bail!("archive missing required {required}");
        }
    }

    let worker_layout = destination.join("beam/worker.beam").is_file();
    let phoenix_layout =
        destination.join("route-plan.json").is_file() && destination.join("release").is_dir();
    match (worker_layout, phoenix_layout) {
        (true, false) | (false, true) => Ok(()),
        (false, false) => {
            bail!("archive must contain either beam/worker.beam or route-plan.json plus release/")
        }
        (true, true) => bail!("archive must not mix worker and Phoenix release layouts"),
    }
}

fn extract_zip(bytes: &[u8], destination: &Path, limits: ArchiveLimits) -> Result<()> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("open ZIP")?;
    let mut state = ExtractionState::default();

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).context("read ZIP entry")?;
        let path = entry
            .enclosed_name()
            .context("ZIP contains path traversal or absolute path")?
            .to_path_buf();

        if entry.is_dir() {
            validate_artifact_directory(&path)?;
            validate_zip_mode(entry.unix_mode(), true)?;
            continue;
        }

        validate_zip_mode(entry.unix_mode(), false)?;
        validate_artifact_path(&path)?;
        register_file(&mut state, &path, limits)?;
        preflight_declared_size(entry.size(), entry.compressed_size(), limits, &state)?;

        let output = destination.join(&path);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&output)
            .with_context(|| format!("create extracted file {}", output.display()))?;
        let copied = copy_bounded(&mut entry, &mut file, limits, state.expanded_bytes)?;
        state.expanded_bytes = state
            .expanded_bytes
            .checked_add(copied)
            .context("expanded byte count overflow")?;
    }

    Ok(())
}

fn extract_tar_gz(bytes: &[u8], destination: &Path, limits: ArchiveLimits) -> Result<()> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut state = ExtractionState::default();

    for entry in archive.entries().context("read tar entries")? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let kind = entry.header().entry_type();

        if kind.is_dir() {
            validate_artifact_directory(&path)?;
            continue;
        }
        if !kind.is_file() {
            bail!("tar bundle may contain regular files and directories only");
        }
        let mode = entry.header().mode().context("read tar entry mode")?;
        if mode & 0o6000 != 0 {
            bail!(
                "tar bundle file {} contains setuid/setgid permission bits",
                path.display()
            );
        }

        validate_artifact_path(&path)?;
        register_file(&mut state, &path, limits)?;
        let declared = entry.header().size().context("read tar entry size")?;
        if declared > limits.max_file_bytes as u64 {
            bail!(
                "archive file {} declares {} bytes; per-file maximum is {} bytes",
                path.display(),
                declared,
                limits.max_file_bytes
            );
        }
        if (state.expanded_bytes as u64).saturating_add(declared) > limits.max_expanded_bytes as u64
        {
            bail!(
                "archive declares more than {} expanded bytes",
                limits.max_expanded_bytes
            );
        }

        let output = destination.join(&path);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&output)
            .with_context(|| format!("create extracted file {}", output.display()))?;
        let copied = copy_bounded(&mut entry, &mut file, limits, state.expanded_bytes)?;
        state.expanded_bytes = state
            .expanded_bytes
            .checked_add(copied)
            .context("expanded byte count overflow")?;
    }

    enforce_ratio(
        state.expanded_bytes as u64,
        bytes.len() as u64,
        "tar.gz bundle",
    )?;
    Ok(())
}

fn validate_zip_mode(mode: Option<u32>, is_dir: bool) -> Result<()> {
    let Some(mode) = mode else {
        return Ok(());
    };
    let file_type = mode & 0o170000;
    let expected = if is_dir { 0o040000 } else { 0o100000 };
    if file_type != 0 && file_type != expected {
        bail!("ZIP bundle contains a symlink or special-mode entry");
    }
    if mode & 0o6000 != 0 {
        bail!("ZIP bundle contains setuid/setgid permission bits");
    }
    Ok(())
}

fn register_file(state: &mut ExtractionState, path: &Path, limits: ArchiveLimits) -> Result<()> {
    if !state.paths.insert(path.to_path_buf()) {
        bail!("duplicate archive path {}", path.display());
    }
    state.files = state
        .files
        .checked_add(1)
        .context("archive file count overflow")?;
    if state.files > limits.max_files {
        bail!("archive contains more than {} files", limits.max_files);
    }
    Ok(())
}

fn preflight_declared_size(
    expanded: u64,
    compressed: u64,
    limits: ArchiveLimits,
    state: &ExtractionState,
) -> Result<()> {
    if expanded > limits.max_file_bytes as u64 {
        bail!(
            "archive file declares {expanded} bytes; per-file maximum is {} bytes",
            limits.max_file_bytes
        );
    }
    if (state.expanded_bytes as u64).saturating_add(expanded) > limits.max_expanded_bytes as u64 {
        bail!(
            "archive declares more than {} expanded bytes",
            limits.max_expanded_bytes
        );
    }
    enforce_ratio(expanded, compressed, "ZIP entry")
}

fn enforce_ratio(expanded: u64, compressed: u64, label: &str) -> Result<()> {
    if expanded >= MIN_RATIO_CHECK_BYTES
        && compressed > 0
        && expanded > compressed.saturating_mul(MAX_COMPRESSION_RATIO)
    {
        bail!("{label} exceeds maximum compression ratio of {MAX_COMPRESSION_RATIO}:1");
    }
    Ok(())
}

fn copy_bounded<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    limits: ArchiveLimits,
    already_expanded: usize,
) -> Result<usize> {
    let mut copied = 0usize;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read)
            .context("archive file byte count overflow")?;
        if copied > limits.max_file_bytes {
            bail!(
                "archive file exceeds {} expanded bytes",
                limits.max_file_bytes
            );
        }
        let total = already_expanded
            .checked_add(copied)
            .context("archive expanded byte count overflow")?;
        if total > limits.max_expanded_bytes {
            bail!(
                "archive exceeds {} total expanded bytes",
                limits.max_expanded_bytes
            );
        }
        writer.write_all(&buffer[..read])?;
    }
    Ok(copied)
}

pub(crate) fn validate_artifact_path(path: &Path) -> Result<()> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("invalid archive path {}", path.display());
    }
    if matches!(
        path.to_str(),
        Some(
            "manifest.json"
                | "admission-report.json"
                | "provenance.json"
                | "attestation.json"
                | "route-plan.json"
        )
    ) {
        return Ok(());
    }
    let components: Vec<_> = path.components().collect();
    if components.len() == 2
        && components[0].as_os_str() == "beam"
        && path.extension().and_then(|ext| ext.to_str()) == Some("beam")
    {
        return Ok(());
    }
    if components.len() >= 2 && components[0].as_os_str() == "release" {
        return Ok(());
    }
    bail!("unexpected file in deployment bundle: {}", path.display())
}

fn validate_artifact_directory(path: &Path) -> Result<()> {
    if path == Path::new("beam") {
        return Ok(());
    }
    let mut components = path.components();
    if matches!(components.next(), Some(Component::Normal(root)) if root == "release") {
        return Ok(());
    }
    bail!(
        "unexpected directory in deployment bundle: {}",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use tar::{Builder as TarBuilder, Header};
    use tempfile::tempdir;
    use zip::{write::SimpleFileOptions, ZipWriter};

    fn required_zip(extra: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, bytes) in [
            ("manifest.json", b"{}".as_slice()),
            ("admission-report.json", b"{}".as_slice()),
            ("provenance.json", b"{}".as_slice()),
            ("attestation.json", b"{}".as_slice()),
            ("beam/worker.beam", b"beam".as_slice()),
        ] {
            zip.start_file(name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
        for (name, bytes) in extra {
            zip.start_file(*name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    fn required_tar(extra: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = TarBuilder::new(encoder);
        for (name, bytes) in [
            ("manifest.json", b"{}".as_slice()),
            ("admission-report.json", b"{}".as_slice()),
            ("provenance.json", b"{}".as_slice()),
            ("attestation.json", b"{}".as_slice()),
            ("beam/worker.beam", b"beam".as_slice()),
        ] {
            append_tar_file(&mut tar, name, bytes);
        }
        for (name, bytes) in extra {
            append_tar_file(&mut tar, name, bytes);
        }
        let encoder = tar.into_inner().unwrap();
        encoder.finish().unwrap()
    }

    fn append_tar_file<W: Write>(tar: &mut TarBuilder<W>, name: &str, bytes: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, Cursor::new(bytes))
            .unwrap();
    }

    fn required_phoenix_tar() -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = TarBuilder::new(encoder);
        for (name, bytes) in [
            ("manifest.json", b"{}".as_slice()),
            ("admission-report.json", b"{}".as_slice()),
            ("provenance.json", b"{}".as_slice()),
            ("attestation.json", b"{}".as_slice()),
            ("route-plan.json", b"{}".as_slice()),
            ("release/bin/demo", b"#!/bin/sh".as_slice()),
            ("release/releases/0.1.0/start.boot", b"boot".as_slice()),
        ] {
            append_tar_file(&mut tar, name, bytes);
        }
        let encoder = tar.into_inner().unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn bounded_phoenix_release_extracts_valid_artifact() {
        let dir = tempdir().unwrap();
        extract_artifact(
            "phoenix-release.tar.gz",
            &required_phoenix_tar(),
            dir.path(),
            ArchiveLimits::for_upload_ceiling(1024 * 1024),
        )
        .unwrap();
        assert!(dir.path().join("route-plan.json").is_file());
        assert!(dir.path().join("release/bin/demo").is_file());
    }

    #[test]
    fn mixed_worker_and_phoenix_layout_is_rejected() {
        let dir = tempdir().unwrap();
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = TarBuilder::new(encoder);
        for (name, bytes) in [
            ("manifest.json", b"{}".as_slice()),
            ("admission-report.json", b"{}".as_slice()),
            ("provenance.json", b"{}".as_slice()),
            ("attestation.json", b"{}".as_slice()),
            ("beam/worker.beam", b"beam".as_slice()),
            ("route-plan.json", b"{}".as_slice()),
            ("release/bin/demo", b"bin".as_slice()),
        ] {
            append_tar_file(&mut tar, name, bytes);
        }
        let bytes = tar.into_inner().unwrap().finish().unwrap();
        let error = extract_artifact(
            "mixed.tar.gz",
            &bytes,
            dir.path(),
            ArchiveLimits::for_upload_ceiling(1024 * 1024),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("must not mix"));
    }

    #[test]
    fn bounded_zip_extracts_valid_artifact() {
        let dir = tempdir().unwrap();
        extract_artifact(
            "worker.zip",
            &required_zip(&[]),
            dir.path(),
            ArchiveLimits::for_upload_ceiling(1024 * 1024),
        )
        .unwrap();
        assert!(dir.path().join("beam/worker.beam").is_file());
    }

    #[test]
    fn duplicate_registration_used_by_zip_is_rejected() {
        let mut state = ExtractionState::default();
        let limits = ArchiveLimits::for_upload_ceiling(1024 * 1024);
        register_file(&mut state, Path::new("manifest.json"), limits).unwrap();
        let error = register_file(&mut state, Path::new("manifest.json"), limits)
            .unwrap_err()
            .to_string();
        assert!(error.contains("duplicate archive path"));
    }

    #[test]
    fn tar_duplicate_canonical_path_is_rejected() {
        let dir = tempdir().unwrap();
        let error = extract_artifact(
            "worker.tar.gz",
            &required_tar(&[("manifest.json", b"duplicate")]),
            dir.path(),
            ArchiveLimits::for_upload_ceiling(1024 * 1024),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("duplicate archive path"));
    }

    #[test]
    fn actual_expanded_bytes_are_bounded_independent_of_compressed_size() {
        let dir = tempdir().unwrap();
        let payload = vec![b'A'; 300 * 1024];
        let archive = required_zip(&[("beam/helper.beam", &payload)]);
        assert!(archive.len() < 64 * 1024);
        let error = extract_artifact(
            "worker.zip",
            &archive,
            dir.path(),
            ArchiveLimits {
                max_expanded_bytes: 128 * 1024,
                max_file_bytes: 512 * 1024,
                max_files: MAX_ARCHIVE_FILES,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("expanded bytes") || error.contains("compression ratio"));
    }

    #[test]
    fn too_many_files_are_rejected() {
        let dir = tempdir().unwrap();
        let extras: Vec<(String, Vec<u8>)> = (0..4)
            .map(|n| (format!("beam/helper{n}.beam"), vec![n as u8]))
            .collect();
        let refs: Vec<(&str, &[u8])> = extras
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
            .collect();
        let error = extract_artifact(
            "worker.zip",
            &required_zip(&refs),
            dir.path(),
            ArchiveLimits {
                max_expanded_bytes: 1024 * 1024,
                max_file_bytes: 1024 * 1024,
                max_files: 8,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("more than 8 files"));
    }

    #[test]
    fn admission_receipt_is_never_customer_extractable() {
        let dir = tempdir().unwrap();
        let error = extract_artifact(
            "worker.zip",
            &required_zip(&[("admission-receipt.json", b"{}")]),
            dir.path(),
            ArchiveLimits::for_upload_ceiling(1024 * 1024),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unexpected file"));
    }

    #[test]
    fn traversal_is_rejected() {
        assert!(validate_artifact_path(Path::new("../escape.beam")).is_err());
        assert!(validate_artifact_path(Path::new("beam/../../escape.beam")).is_err());
        assert!(validate_artifact_path(Path::new("beam/nested/helper.beam")).is_err());
    }

    #[test]
    fn zip_special_modes_are_rejected() {
        assert!(validate_zip_mode(Some(0o120777), false).is_err());
        assert!(validate_zip_mode(Some(0o060600), false).is_err());
        assert!(validate_zip_mode(Some(0o104755), false).is_err());
        assert!(validate_zip_mode(Some(0o102755), false).is_err());
        assert!(validate_zip_mode(Some(0o100755), false).is_ok());
        assert!(validate_zip_mode(Some(0o040755), true).is_ok());
    }

    #[test]
    fn tar_setuid_release_file_is_rejected() {
        let dir = tempdir().unwrap();
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = TarBuilder::new(encoder);
        for (name, bytes) in [
            ("manifest.json", b"{}".as_slice()),
            ("admission-report.json", b"{}".as_slice()),
            ("provenance.json", b"{}".as_slice()),
            ("attestation.json", b"{}".as_slice()),
            ("route-plan.json", b"{}".as_slice()),
            ("release/releases/0.1.0/start.boot", b"boot".as_slice()),
        ] {
            append_tar_file(&mut tar, name, bytes);
        }
        let mut header = Header::new_gnu();
        let bytes = b"#!/bin/sh";
        header.set_size(bytes.len() as u64);
        header.set_mode(0o4755);
        header.set_cksum();
        tar.append_data(&mut header, "release/bin/demo", Cursor::new(bytes))
            .unwrap();
        let archive = tar.into_inner().unwrap().finish().unwrap();

        let error = extract_artifact(
            "phoenix-release.tar.gz",
            &archive,
            dir.path(),
            ArchiveLimits::for_upload_ceiling(1024 * 1024),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("setuid/setgid"));
    }
}
