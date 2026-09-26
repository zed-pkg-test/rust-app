use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

const PLAN_SCHEMA: &str = "ores.provider-benchmark.plan/v1";
const TARGET_SCHEMA: &str = "ores.provider-benchmark.target-receipt/v1";
const AGGREGATE_SCHEMA: &str = "ores.provider-benchmark.aggregate-receipt/v1";
const OWNED_ENV_PREFIX: &str = "ORES_PROVIDER_BENCHMARK_";

#[derive(Debug)]
pub struct BenchmarkOptions {
    pub root: PathBuf,
    pub plan: PathBuf,
    pub out: Option<PathBuf>,
    pub check: bool,
    pub json: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BenchmarkPlan {
    schema: String,
    release_id: String,
    request_corpus_sha256: String,
    pricing_snapshot: PricingSnapshot,
    targets: Vec<BenchmarkTarget>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PricingSnapshot {
    as_of: String,
    currency: String,
    source: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourceProfile {
    architecture: String,
    memory_mb: Option<u64>,
    cpu_millis: Option<u64>,
    concurrency: Option<u64>,
    mode: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BenchmarkTarget {
    id: String,
    provider: String,
    region: String,
    artifact_receipts: BTreeMap<String, String>,
    resource_profile: ResourceProfile,
    run: BenchmarkCommand,
    receipt: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BenchmarkCommand {
    cwd: Option<String>,
    argv: Vec<String>,
    #[serde(default)]
    inherit_env: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TargetReceipt {
    schema: String,
    target_id: String,
    provider: String,
    region: String,
    release_id: String,
    request_corpus_sha256: String,
    artifact_receipts: BTreeMap<String, String>,
    resource_profile: ResourceProfile,
    samples: Samples,
    billing: Billing,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Samples {
    request_count: u64,
    error_count: u64,
    throttled_count: u64,
    cold_count: u64,
    warm_count: u64,
    duration_ms: u64,
    throughput_rps: f64,
    latency: Latency,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Latency {
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Billing {
    basis: String,
    amount: f64,
    currency: String,
    pricing_snapshot_as_of: String,
    billable_duration_ms: Option<u64>,
    billable_instance_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AggregateReceipt {
    schema: &'static str,
    plan_sha256: String,
    release_id: String,
    request_corpus_sha256: String,
    pricing_snapshot: PricingSnapshot,
    comparable: bool,
    comparability_issues: Vec<String>,
    targets: Vec<TargetReceipt>,
}

pub fn run(options: BenchmarkOptions) -> Result<()> {
    let root = fs::canonicalize(&options.root)
        .with_context(|| format!("resolve benchmark root {}", options.root.display()))?;
    if !root.is_dir() {
        bail!("benchmark root must be a directory");
    }

    let plan_path = confined_existing_file(&root, &options.plan)?;
    let plan_bytes = fs::read(&plan_path)
        .with_context(|| format!("read benchmark plan {}", plan_path.display()))?;
    let plan: BenchmarkPlan = serde_json::from_slice(&plan_bytes)
        .with_context(|| format!("parse benchmark plan {}", plan_path.display()))?;
    validate_plan(&root, &plan, !options.check)?;

    if options.check {
        if options.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema": PLAN_SCHEMA,
                    "mode": "check",
                    "planSha256": sha256_hex(&plan_bytes),
                    "releaseId": plan.release_id,
                    "requestCorpusSha256": plan.request_corpus_sha256,
                    "targets": plan.targets.iter().map(|target| &target.id).collect::<Vec<_>>(),
                }))?
            );
        } else {
            println!(
                "bmscl benchmark check: {} target(s), release {}",
                plan.targets.len(),
                plan.release_id
            );
        }
        return Ok(());
    }

    let mut receipts = Vec::with_capacity(plan.targets.len());
    for target in &plan.targets {
        let receipt_path = confined_new_file_path(&root, Path::new(&target.receipt))?;
        if receipt_path.exists() {
            bail!(
                "benchmark target {:?} receipt {} already exists; archive or remove it before a new run",
                target.id,
                receipt_path.display()
            );
        }
        run_command(&root, &plan, target, &receipt_path)?;
        let receipt = read_receipt(&receipt_path)?;
        validate_receipt(&plan, target, &receipt)?;
        receipts.push(receipt);
    }

    let comparability_issues = comparability_issues(&receipts);
    let aggregate = AggregateReceipt {
        schema: AGGREGATE_SCHEMA,
        plan_sha256: sha256_hex(&plan_bytes),
        release_id: plan.release_id,
        request_corpus_sha256: plan.request_corpus_sha256,
        pricing_snapshot: plan.pricing_snapshot,
        comparable: comparability_issues.is_empty(),
        comparability_issues,
        targets: receipts,
    };
    let encoded = serde_json::to_vec_pretty(&aggregate)?;

    if let Some(out) = options.out {
        let path = confined_new_file_path(&root, &out)?;
        write_new(&path, &encoded)?;
    }

    if options.json {
        println!("{}", String::from_utf8(encoded).expect("JSON is UTF-8"));
    } else {
        println!(
            "bmscl benchmark: {} target(s), release {}, comparable={}",
            aggregate.targets.len(),
            aggregate.release_id,
            aggregate.comparable
        );
        for target in &aggregate.targets {
            println!(
                "  {} {} {}: p95={:.3}ms rps={:.3} cost={} {:.6} ({})",
                target.target_id,
                target.provider,
                target.region,
                target.samples.latency.p95_ms,
                target.samples.throughput_rps,
                target.billing.currency,
                target.billing.amount,
                target.billing.basis
            );
        }
        for issue in &aggregate.comparability_issues {
            println!("  not-comparable: {issue}");
        }
    }
    Ok(())
}

fn validate_plan(root: &Path, plan: &BenchmarkPlan, require_runtime_env: bool) -> Result<()> {
    if plan.schema != PLAN_SCHEMA {
        bail!(
            "unsupported benchmark plan schema {:?}; expected {:?}",
            plan.schema,
            PLAN_SCHEMA
        );
    }
    if plan.release_id.trim().is_empty() {
        bail!("benchmark releaseId must not be empty");
    }
    validate_sha256("requestCorpusSha256", &plan.request_corpus_sha256)?;
    validate_pricing(&plan.pricing_snapshot)?;
    if plan.targets.is_empty() {
        bail!("benchmark plan must contain at least one target");
    }

    let mut ids = BTreeSet::new();
    let mut receipt_paths = BTreeSet::new();
    for target in &plan.targets {
        validate_id(&target.id)?;
        if !ids.insert(&target.id) {
            bail!("duplicate benchmark target id {:?}", target.id);
        }
        if target.provider.trim().is_empty() || target.region.trim().is_empty() {
            bail!(
                "benchmark target {:?} requires provider and region",
                target.id
            );
        }
        if target.artifact_receipts.is_empty() {
            bail!(
                "benchmark target {:?} must bind at least one artifact receipt digest",
                target.id
            );
        }
        for (name, digest) in &target.artifact_receipts {
            if name.trim().is_empty() {
                bail!(
                    "benchmark target {:?} has an empty artifact receipt key",
                    target.id
                );
            }
            validate_sha256("artifact receipt digest", digest)?;
        }
        validate_resource(&target.resource_profile)?;
        validate_command(root, &target.run, &target.id, require_runtime_env)?;
        let receipt_path = confined_new_file_path(root, Path::new(&target.receipt))?;
        if !receipt_paths.insert(receipt_path) {
            bail!("benchmark targets must not share an output receipt path");
        }
    }
    Ok(())
}

fn validate_pricing(pricing: &PricingSnapshot) -> Result<()> {
    if pricing.as_of.trim().is_empty() || pricing.source.trim().is_empty() {
        bail!("pricing snapshot requires non-empty asOf and source");
    }
    if pricing.currency.len() != 3
        || !pricing
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        bail!("pricing snapshot currency must be a three-letter uppercase code");
    }
    Ok(())
}

fn validate_resource(profile: &ResourceProfile) -> Result<()> {
    if profile.architecture.trim().is_empty()
        || profile.memory_mb == Some(0)
        || profile.cpu_millis == Some(0)
        || profile.concurrency == Some(0)
        || profile
            .mode
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
    {
        bail!("benchmark resource profile contains an empty or zero value");
    }
    Ok(())
}

fn validate_command(
    root: &Path,
    command: &BenchmarkCommand,
    target_id: &str,
    require_runtime_env: bool,
) -> Result<()> {
    if command.argv.is_empty() || command.argv.iter().any(|value| value.contains(' ')) {
        bail!(
            "benchmark target {target_id:?} command argv must be non-empty and contain no NUL bytes"
        );
    }
    if let Some(cwd) = &command.cwd {
        let _ = confined_existing_dir(root, Path::new(cwd))?;
    }

    let mut seen = BTreeSet::new();
    for name in &command.inherit_env {
        if !valid_env_name(name) || name.starts_with(OWNED_ENV_PREFIX) {
            bail!(
                "benchmark target {target_id:?} has invalid or benchmark-owned inheritEnv name {name:?}"
            );
        }
        if !seen.insert(name) {
            bail!("benchmark target {target_id:?} repeats inheritEnv name {name:?}");
        }
        if require_runtime_env && env::var_os(name).is_none() {
            bail!(
                "benchmark target {target_id:?} requires environment variable {name:?}, but it is not set"
            );
        }
    }
    Ok(())
}

fn run_command(
    root: &Path,
    plan: &BenchmarkPlan,
    target: &BenchmarkTarget,
    receipt_path: &Path,
) -> Result<()> {
    let (program, command_args) = target
        .run
        .argv
        .split_first()
        .context("benchmark command argv is empty")?;
    let cwd = match target.run.cwd.as_deref() {
        Some(cwd) => confined_existing_dir(root, Path::new(cwd))?,
        None => root.to_path_buf(),
    };

    eprintln!(
        "bmscl: benchmark {}: executable={:?} (arguments redacted)",
        target.id, program
    );

    let mut command = Command::new(program);
    command
        .args(command_args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .env_clear();
    preserve_exec_environment(&mut command);
    for name in &target.run.inherit_env {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env("ORES_PROVIDER_BENCHMARK_TARGET_ID", &target.id)
        .env("ORES_PROVIDER_BENCHMARK_PROVIDER", &target.provider)
        .env("ORES_PROVIDER_BENCHMARK_REGION", &target.region)
        .env("ORES_PROVIDER_BENCHMARK_RELEASE_ID", &plan.release_id)
        .env(
            "ORES_PROVIDER_BENCHMARK_REQUEST_CORPUS_SHA256",
            &plan.request_corpus_sha256,
        )
        .env("ORES_PROVIDER_BENCHMARK_RECEIPT", receipt_path)
        .env(
            "ORES_PROVIDER_BENCHMARK_PRICING_AS_OF",
            &plan.pricing_snapshot.as_of,
        )
        .env(
            "ORES_PROVIDER_BENCHMARK_PRICING_CURRENCY",
            &plan.pricing_snapshot.currency,
        );

    let status = command
        .status()
        .with_context(|| format!("launch benchmark command {program:?}"))?;
    if !status.success() {
        bail!(
            "benchmark target {:?} command {program:?} exited with {status}",
            target.id
        );
    }
    if !receipt_path.is_file() {
        bail!(
            "benchmark target {:?} succeeded but did not create receipt {}",
            target.id,
            receipt_path.display()
        );
    }
    Ok(())
}

fn read_receipt(path: &Path) -> Result<TargetReceipt> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect benchmark receipt {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "benchmark receipt {} must be a regular non-symlink file",
            path.display()
        );
    }
    let bytes =
        fs::read(path).with_context(|| format!("read benchmark receipt {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse benchmark receipt {}", path.display()))
}

fn validate_receipt(
    plan: &BenchmarkPlan,
    target: &BenchmarkTarget,
    receipt: &TargetReceipt,
) -> Result<()> {
    if receipt.schema != TARGET_SCHEMA
        || receipt.target_id != target.id
        || receipt.provider != target.provider
        || receipt.region != target.region
        || receipt.release_id != plan.release_id
        || receipt.request_corpus_sha256 != plan.request_corpus_sha256
        || receipt.artifact_receipts != target.artifact_receipts
        || receipt.resource_profile != target.resource_profile
    {
        bail!(
            "benchmark receipt for target {:?} does not match its immutable plan identity",
            target.id
        );
    }
    validate_samples(&receipt.samples)?;
    validate_billing(&plan.pricing_snapshot, &receipt.billing)
}

fn validate_samples(samples: &Samples) -> Result<()> {
    if samples.request_count == 0
        || samples.duration_ms == 0
        || samples.error_count > samples.request_count
        || samples.throttled_count > samples.request_count
        || samples.cold_count.saturating_add(samples.warm_count) > samples.request_count
        || !finite_nonnegative(samples.throughput_rps)
        || !finite_nonnegative(samples.latency.p50_ms)
        || !finite_nonnegative(samples.latency.p95_ms)
        || !finite_nonnegative(samples.latency.p99_ms)
        || samples.latency.p50_ms > samples.latency.p95_ms
        || samples.latency.p95_ms > samples.latency.p99_ms
    {
        bail!("benchmark sample metrics are internally inconsistent");
    }
    Ok(())
}

fn validate_billing(pricing: &PricingSnapshot, billing: &Billing) -> Result<()> {
    if !matches!(billing.basis.as_str(), "measured" | "estimated")
        || !finite_nonnegative(billing.amount)
        || billing.currency != pricing.currency
        || billing.pricing_snapshot_as_of != pricing.as_of
    {
        bail!(
            "benchmark billing must declare measured|estimated basis and match the pricing snapshot"
        );
    }
    Ok(())
}

fn comparability_issues(receipts: &[TargetReceipt]) -> Vec<String> {
    let Some(first) = receipts.first() else {
        return vec!["no target receipts".to_owned()];
    };
    receipts
        .iter()
        .skip(1)
        .filter(|receipt| receipt.resource_profile != first.resource_profile)
        .map(|receipt| {
            format!(
                "resource profile for {} differs from {}",
                receipt.target_id, first.target_id
            )
        })
        .collect()
}

fn finite_nonnegative(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

fn validate_id(value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    let valid = !value.is_empty()
        && value.len() <= 63
        && matches!(bytes.next(), Some(first) if first.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        });
    if !valid {
        bail!("invalid benchmark target id {value:?}");
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} must be a 64-character lowercase SHA-256");
    }
    Ok(())
}

fn valid_env_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn preserve_exec_environment(command: &mut Command) {
    if let Some(path) = env::var_os("PATH") {
        command.env("PATH", path);
    }
    #[cfg(windows)]
    for name in ["SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
}

fn confined_existing_file(root: &Path, configured: &Path) -> Result<PathBuf> {
    validate_relative_path(configured)?;
    reject_symlink_components(root, configured, false)?;
    let candidate = root.join(configured);
    let metadata = fs::symlink_metadata(&candidate)
        .with_context(|| format!("inspect {}", candidate.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{} must be a regular non-symlink file", candidate.display());
    }
    let path =
        fs::canonicalize(&candidate).with_context(|| format!("resolve {}", candidate.display()))?;
    if !path.starts_with(root) {
        bail!("path {} escapes benchmark root", candidate.display());
    }
    Ok(path)
}

fn confined_existing_dir(root: &Path, configured: &Path) -> Result<PathBuf> {
    let path = confined_existing(root, configured)?;
    if !path.is_dir() {
        bail!("{} must be a directory", path.display());
    }
    Ok(path)
}

fn confined_existing(root: &Path, configured: &Path) -> Result<PathBuf> {
    validate_relative_path(configured)?;
    reject_symlink_components(root, configured, false)?;
    let candidate = root.join(configured);
    let resolved =
        fs::canonicalize(&candidate).with_context(|| format!("resolve {}", candidate.display()))?;
    if !resolved.starts_with(root) {
        bail!("path {} escapes benchmark root", candidate.display());
    }
    Ok(resolved)
}

fn confined_new_file_path(root: &Path, configured: &Path) -> Result<PathBuf> {
    validate_relative_path(configured)?;
    reject_symlink_components(root, configured, true)?;
    let candidate = root.join(configured);
    let parent = candidate
        .parent()
        .context("benchmark output path has no parent")?;
    let resolved_parent = fs::canonicalize(parent)
        .with_context(|| format!("resolve output parent {}", parent.display()))?;
    if !resolved_parent.starts_with(root) {
        bail!("output path {} escapes benchmark root", candidate.display());
    }
    Ok(resolved_parent.join(
        candidate
            .file_name()
            .context("benchmark output path has no filename")?,
    ))
}

fn reject_symlink_components(
    root: &Path,
    configured: &Path,
    allow_missing_final: bool,
) -> Result<()> {
    let components = configured.components().collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            bail!(
                "benchmark path {:?} must be normalized and root-relative",
                configured
            );
        };
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "benchmark path crosses symlink component {}",
                    current.display()
                );
            }
            Ok(_) => {}
            Err(error)
                if allow_missing_final
                    && index + 1 == components.len()
                    && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect benchmark path {}", current.display()));
            }
        }
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!(
            "benchmark path {:?} must be normalized and root-relative",
            path
        );
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("finish {}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource(memory_mb: u64) -> ResourceProfile {
        ResourceProfile {
            architecture: "linux/arm64".to_owned(),
            memory_mb: Some(memory_mb),
            cpu_millis: Some(1000),
            concurrency: Some(8),
            mode: Some("request".to_owned()),
        }
    }

    fn receipt(id: &str, memory_mb: u64) -> TargetReceipt {
        TargetReceipt {
            schema: TARGET_SCHEMA.to_owned(),
            target_id: id.to_owned(),
            provider: "test".to_owned(),
            region: "test-1".to_owned(),
            release_id: "release".to_owned(),
            request_corpus_sha256: "a".repeat(64),
            artifact_receipts: BTreeMap::from([("app".to_owned(), "b".repeat(64))]),
            resource_profile: resource(memory_mb),
            samples: Samples {
                request_count: 100,
                error_count: 0,
                throttled_count: 0,
                cold_count: 10,
                warm_count: 90,
                duration_ms: 1000,
                throughput_rps: 100.0,
                latency: Latency {
                    p50_ms: 1.0,
                    p95_ms: 2.0,
                    p99_ms: 3.0,
                },
            },
            billing: Billing {
                basis: "estimated".to_owned(),
                amount: 0.01,
                currency: "USD".to_owned(),
                pricing_snapshot_as_of: "2026-09-25".to_owned(),
                billable_duration_ms: Some(1000),
                billable_instance_ms: None,
            },
        }
    }

    #[test]
    fn resource_mismatch_is_not_comparable() {
        assert!(comparability_issues(&[receipt("a", 512), receipt("b", 512)]).is_empty());
        assert_eq!(
            comparability_issues(&[receipt("a", 512), receipt("b", 1024)]).len(),
            1
        );
    }

    #[test]
    fn invalid_metrics_fail_closed() {
        let mut samples = receipt("a", 512).samples;
        assert!(validate_samples(&samples).is_ok());
        samples.latency.p50_ms = 4.0;
        assert!(validate_samples(&samples).is_err());
    }

    #[test]
    fn benchmark_owned_environment_cannot_be_inherited() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command = BenchmarkCommand {
            cwd: None,
            argv: vec!["true".to_owned()],
            inherit_env: vec!["ORES_PROVIDER_BENCHMARK_RELEASE_ID".to_owned()],
        };
        assert!(validate_command(temp.path(), &command, "fixture", false).is_err());
    }

    #[test]
    fn check_mode_does_not_require_provider_credentials() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = format!("BMSCL_BENCHMARK_MISSING_{}", std::process::id());
        env::remove_var(&missing);
        let command = BenchmarkCommand {
            cwd: None,
            argv: vec!["true".to_owned()],
            inherit_env: vec![missing],
        };
        assert!(validate_command(temp.path(), &command, "fixture", false).is_ok());
        assert!(validate_command(temp.path(), &command, "fixture", true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_symlink_components_are_rejected() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let real = temp.path().join("real");
        fs::create_dir(&real).expect("real dir");
        fs::write(real.join("plan.json"), b"{}").expect("plan");
        symlink("real", temp.path().join("link")).expect("symlink");

        assert!(confined_existing_file(temp.path(), Path::new("link/plan.json")).is_err());
        assert!(confined_new_file_path(temp.path(), Path::new("link/out.json")).is_err());
    }

    #[test]
    fn traversal_output_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        assert!(confined_new_file_path(temp.path(), Path::new("../escape.json")).is_err());
    }
}
