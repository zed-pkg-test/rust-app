use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup/beamscale";
const DEFAULT_IDENTITY_ROOT: &str = "/run/bmscl/runtime-identities";
const MAX_IDENTITY_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RuntimeIdentity {
    runtime_id: String,
    user_id: String,
    tenant_id: String,
    deployment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_id: Option<String>,
}

#[derive(Debug)]
struct Args {
    cgroup_root: PathBuf,
    cgroup_path: PathBuf,
    identity_root: PathBuf,
    expected_runtime_id: Option<String>,
    user_id: String,
    tenant_id: String,
    deployment_id: String,
    invocation_id: Option<String>,
}

fn main() {
    match run(env::args().skip(1)) {
        Ok(path) => println!("{}", path.display()),
        Err(error) => {
            eprintln!("bmscl-runtime-identity-writer: {error}");
            std::process::exit(2);
        }
    }
}

fn run<I>(args: I) -> Result<PathBuf, String>
where
    I: IntoIterator<Item = String>,
{
    let args = parse_args(args)?;
    validate_subject("user_id", &args.user_id)?;
    validate_subject("tenant_id", &args.tenant_id)?;
    validate_subject("deployment_id", &args.deployment_id)?;
    if let Some(invocation_id) = args.invocation_id.as_deref() {
        validate_subject("invocation_id", invocation_id)?;
    }

    let (cgroup_root, cgroup_path) = validate_managed_cgroup(&args.cgroup_root, &args.cgroup_path)?;
    let runtime_id = runtime_id_for_cgroup(&cgroup_root, &cgroup_path)?;
    if let Some(expected) = args.expected_runtime_id.as_deref() {
        validate_runtime_id(expected)?;
        if expected != runtime_id {
            return Err(
                "--runtime-id does not match deterministic managed-cgroup mapping".to_owned(),
            );
        }
    }

    let identity = RuntimeIdentity {
        runtime_id,
        user_id: args.user_id,
        tenant_id: args.tenant_id,
        deployment_id: args.deployment_id,
        invocation_id: args.invocation_id,
    };
    let identity_root = validate_identity_root(&args.identity_root)?;
    let path = publish_identity_idempotently(&identity_root, &identity)?;
    validate_published_file(&path)?;
    Ok(path)
}

fn parse_args<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut cgroup_root = PathBuf::from(DEFAULT_CGROUP_ROOT);
    let mut cgroup_path = None;
    let mut identity_root = PathBuf::from(DEFAULT_IDENTITY_ROOT);
    let mut expected_runtime_id = None;
    let mut user_id = None;
    let mut tenant_id = None;
    let mut deployment_id = None;
    let mut invocation_id = None;

    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_str() {
            "--cgroup-root" => cgroup_root = PathBuf::from(value),
            "--cgroup-path" => cgroup_path = Some(PathBuf::from(value)),
            "--identity-root" => identity_root = PathBuf::from(value),
            "--runtime-id" => expected_runtime_id = Some(value),
            "--user-id" => user_id = Some(value),
            "--tenant-id" => tenant_id = Some(value),
            "--deployment-id" => deployment_id = Some(value),
            "--invocation-id" => invocation_id = Some(value),
            _ => return Err(format!("unknown argument {flag}")),
        }
    }

    Ok(Args {
        cgroup_root,
        cgroup_path: cgroup_path.ok_or_else(|| "--cgroup-path is required".to_owned())?,
        identity_root,
        expected_runtime_id,
        user_id: user_id.ok_or_else(|| "--user-id is required".to_owned())?,
        tenant_id: tenant_id.ok_or_else(|| "--tenant-id is required".to_owned())?,
        deployment_id: deployment_id.ok_or_else(|| "--deployment-id is required".to_owned())?,
        invocation_id,
    })
}

fn validate_runtime_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("runtime_id must be 1-128 ASCII letters, digits, '.', '_' or '-'".to_owned());
    }
    Ok(())
}

fn validate_subject(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(format!(
            "{label} must be 1-256 printable non-whitespace ASCII characters"
        ));
    }
    Ok(())
}

fn validate_managed_cgroup(root: &Path, cgroup: &Path) -> Result<(PathBuf, PathBuf), String> {
    if !root.is_absolute() || !cgroup.is_absolute() {
        return Err("cgroup root and path must be absolute".to_owned());
    }
    reject_non_normal_components(root, "cgroup root")?;
    reject_non_normal_components(cgroup, "cgroup path")?;

    let root = fs::canonicalize(root)
        .map_err(|error| format!("canonicalize cgroup root {}: {error}", root.display()))?;
    let cgroup = fs::canonicalize(cgroup)
        .map_err(|error| format!("canonicalize cgroup path {}: {error}", cgroup.display()))?;
    if cgroup == root || !cgroup.starts_with(&root) {
        return Err(format!(
            "runtime cgroup {} is outside managed subtree {}",
            cgroup.display(),
            root.display()
        ));
    }
    let metadata = fs::metadata(&cgroup)
        .map_err(|error| format!("read cgroup metadata {}: {error}", cgroup.display()))?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("runtime cgroup must be root-owned and not group/world writable".to_owned());
    }
    Ok((root, cgroup))
}

fn runtime_id_for_cgroup(root: &Path, cgroup: &Path) -> Result<String, String> {
    if cgroup == root || !cgroup.starts_with(root) {
        return Err("cannot derive runtime id outside managed cgroup subtree".to_owned());
    }
    let relative = cgroup
        .strip_prefix(root)
        .map_err(|_| "managed cgroup could not be made root-relative".to_owned())?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("managed cgroup relative path contains non-normal components".to_owned());
    }
    let mut hasher = Sha256::new();
    hasher.update(relative.as_os_str().as_bytes());
    Ok(format!("rt_{:x}", hasher.finalize()))
}

fn validate_identity_root(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("identity root must be absolute".to_owned());
    }
    reject_non_normal_components(path, "identity root")?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("read identity root {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err("identity root must be a real directory, not a symlink".to_owned());
    }
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("identity root must be root-owned and not group/world writable".to_owned());
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("canonicalize identity root {}: {error}", path.display()))?;
    if canonical != path {
        return Err("identity root must not traverse symlinked components".to_owned());
    }
    Ok(canonical)
}

fn reject_non_normal_components(path: &Path, label: &str) -> Result<(), String> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(format!("{label} may not contain '.' or '..' components"));
    }
    Ok(())
}

fn publish_identity_idempotently(
    root: &Path,
    identity: &RuntimeIdentity,
) -> Result<PathBuf, String> {
    let path = root.join(format!("{}.json", identity.runtime_id));
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(mut file) => {
            serde_json::to_writer_pretty(&mut file, identity)
                .map_err(|error| format!("serialize identity {}: {error}", path.display()))?;
            file.write_all(b"\n")
                .map_err(|error| format!("finish identity {}: {error}", path.display()))?;
            file.sync_all()
                .map_err(|error| format!("fsync identity {}: {error}", path.display()))?;
            File::open(root)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("fsync identity root {}: {error}", root.display()))?;
            Ok(path)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let bytes = read_existing_identity(&path)?;
            if identity_bytes_match(&bytes, identity)? {
                Ok(path)
            } else {
                Err(format!(
                    "runtime identity {} already exists with conflicting immutable subjects",
                    path.display()
                ))
            }
        }
        Err(error) => Err(format!(
            "create immutable identity {}: {error}",
            path.display()
        )),
    }
}

fn read_existing_identity(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("open existing identity {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect existing identity {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err("published runtime identity must be a regular file".to_owned());
    }
    if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(
            "published runtime identity must be root-owned with mode 0600 or stricter".to_owned(),
        );
    }
    if metadata.len() > MAX_IDENTITY_BYTES {
        return Err("published runtime identity exceeds 16 KiB".to_owned());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_IDENTITY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read existing identity {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_IDENTITY_BYTES {
        return Err("published runtime identity exceeds 16 KiB".to_owned());
    }
    Ok(bytes)
}

fn identity_bytes_match(bytes: &[u8], identity: &RuntimeIdentity) -> Result<bool, String> {
    let existing: RuntimeIdentity = serde_json::from_slice(bytes)
        .map_err(|parse_error| format!("parse existing runtime identity: {parse_error}"))?;
    Ok(existing == *identity)
}

fn validate_published_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("read identity metadata {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("published runtime identity must be a regular file".to_owned());
    }
    if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(
            "published runtime identity must be root-owned with mode 0600 or stricter".to_owned(),
        );
    }
    if metadata.len() > MAX_IDENTITY_BYTES {
        return Err("published runtime identity exceeds 16 KiB".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn identity(runtime_id: &str) -> RuntimeIdentity {
        RuntimeIdentity {
            runtime_id: runtime_id.to_owned(),
            user_id: "usr_test".to_owned(),
            tenant_id: "ten_test".to_owned(),
            deployment_id: "dep_test".to_owned(),
            invocation_id: Some("inv_test".to_owned()),
        }
    }

    #[test]
    fn runtime_id_is_safe_for_identity_filename() {
        assert!(validate_runtime_id("rt_01k_test-1.2").is_ok());
        assert!(validate_runtime_id("../escape").is_err());
        assert!(validate_runtime_id("with/slash").is_err());
        assert!(validate_runtime_id("").is_err());
    }

    #[test]
    fn runtime_id_hashes_full_relative_cgroup_path() {
        let root = Path::new("/sys/fs/cgroup/beamscale");
        let a = runtime_id_for_cgroup(root, Path::new("/sys/fs/cgroup/beamscale/a/0/1")).unwrap();
        let b = runtime_id_for_cgroup(root, Path::new("/sys/fs/cgroup/beamscale/b/0/1")).unwrap();
        assert!(a.starts_with("rt_"));
        assert_eq!(a.len(), 67);
        assert_ne!(a, b);
        assert_eq!(
            a,
            runtime_id_for_cgroup(root, Path::new("/sys/fs/cgroup/beamscale/a/0/1")).unwrap()
        );
    }

    #[test]
    fn exact_identity_content_is_idempotent_but_conflict_is_rejected() {
        let temp = TempDir::new().unwrap();
        let first = identity("rt_test");
        let path = publish_identity_idempotently(temp.path(), &first).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(identity_bytes_match(&original, &first).unwrap());

        let mut conflicting = first;
        conflicting.user_id = "usr_attacker".to_owned();
        assert!(!identity_bytes_match(&original, &conflicting).unwrap());
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn parser_requires_host_cgroup_and_authenticated_subjects() {
        let args = parse_args([
            "--cgroup-path".to_owned(),
            "/sys/fs/cgroup/beamscale/ten/shard/1".to_owned(),
            "--user-id".to_owned(),
            "usr_test".to_owned(),
            "--tenant-id".to_owned(),
            "ten_test".to_owned(),
            "--deployment-id".to_owned(),
            "dep_test".to_owned(),
        ])
        .unwrap();
        assert_eq!(args.user_id, "usr_test");
        assert_eq!(args.tenant_id, "ten_test");
        assert_eq!(args.deployment_id, "dep_test");
        assert!(args.expected_runtime_id.is_none());
    }
}
