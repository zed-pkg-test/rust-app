use serde::Deserialize;
use std::{collections::{HashMap, HashSet}, env, fs, path::Path};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    schema_version: String,
    coverage_state: String,
    repositories: Vec<Repository>,
    certifications: Vec<Certification>,
    formal_evidence: Vec<FormalEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Repository {
    id: String,
    observed_commit: String,
    inspection_state: String,
    role: String,
    languages: Vec<String>,
    contract_authorities: Vec<String>,
    release_mechanism: String,
    test_repositories: Vec<String>,
    deployment_consumers: Vec<String>,
    dependencies: Vec<Dependency>,
}

#[derive(Debug, Deserialize)]
struct Dependency {
    repository: String,
    kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Certification {
    receipt_id: String,
    source_repository: String,
    source_commit: String,
    execution_repository: String,
    execution_commit: String,
    run_url: String,
    status: String,
    infrastructure_state: String,
    commands: Vec<String>,
    toolchains: Vec<String>,
    dependency_commits: Vec<DependencyCommit>,
    artifact_digests: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DependencyCommit {
    repository: String,
    commit: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FormalEvidence {
    claim_id: String,
    repository: String,
    status: String,
    risk_classes: Vec<String>,
    invariants: Vec<String>,
    model_paths: Vec<String>,
    implementation_paths: Vec<String>,
    test_paths: Vec<String>,
    assumptions: Vec<String>,
    bounds: Vec<String>,
    broken_implementation_test: String,
    evidence_receipts: Vec<String>,
}

fn fail(message: impl Into<String>) -> Result<(), String> {
    Err(message.into())
}

fn non_empty(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        fail(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn is_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else { return false; };
    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn valid_repo_id(value: &str) -> bool {
    let mut parts = value.split('/');
    let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    [owner, repo].into_iter().all(|part| {
        !part.is_empty()
            && part.len() <= 100
            && part.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    })
}

fn validate(snapshot: &Snapshot) -> Result<(), String> {
    if snapshot.schema_version != "ores.portfolio-governance.v1" {
        return fail("schemaVersion must be ores.portfolio-governance.v1");
    }
    if !matches!(snapshot.coverage_state.as_str(), "partial" | "complete") {
        return fail("coverageState must be partial or complete");
    }
    if snapshot.repositories.is_empty() {
        return fail("repositories must not be empty");
    }

    let mut repos = HashSet::new();
    for repo in &snapshot.repositories {
        if !valid_repo_id(&repo.id) {
            return fail(format!("invalid repository id {}", repo.id));
        }
        if !repos.insert(repo.id.as_str()) {
            return fail(format!("duplicate repository {}", repo.id));
        }
        if !is_sha(&repo.observed_commit) {
            return fail(format!("{} observedCommit must be exact lowercase 40-hex SHA", repo.id));
        }
        if !matches!(repo.inspection_state.as_str(), "reviewed" | "uninspected") {
            return fail(format!("{} has invalid inspectionState", repo.id));
        }
        for (label, values) in [
            ("languages", &repo.languages),
            ("contractAuthorities", &repo.contract_authorities),
        ] {
            if repo.inspection_state == "reviewed" && values.is_empty() {
                return fail(format!("{} reviewed repository needs {label}", repo.id));
            }
            for value in values {
                non_empty(value, &format!("{}.{}", repo.id, label))?;
            }
        }
        non_empty(&repo.role, &format!("{}.role", repo.id))?;
        non_empty(&repo.release_mechanism, &format!("{}.releaseMechanism", repo.id))?;
        for value in repo.test_repositories.iter().chain(repo.deployment_consumers.iter()) {
            if !valid_repo_id(value) {
                return fail(format!("{} references invalid repository {}", repo.id, value));
            }
        }
        for dep in &repo.dependencies {
            if !valid_repo_id(&dep.repository) || dep.kind.trim().is_empty() {
                return fail(format!("{} has invalid dependency edge", repo.id));
            }
        }
    }
    if snapshot.coverage_state == "complete"
        && snapshot.repositories.iter().any(|r| r.inspection_state != "reviewed")
    {
        return fail("complete coverage cannot contain uninspected repositories");
    }
    for repo in &snapshot.repositories {
        for dep in &repo.dependencies {
            if !repos.contains(dep.repository.as_str()) {
                return fail(format!(
                    "{} dependency {} is absent; add it as reviewed or uninspected",
                    repo.id, dep.repository
                ));
            }
        }
    }

    let mut receipts = HashMap::new();
    for receipt in &snapshot.certifications {
        if receipt.receipt_id.trim().is_empty() || receipts.contains_key(receipt.receipt_id.as_str()) {
            return fail(format!("invalid or duplicate receiptId {}", receipt.receipt_id));
        }
        if !repos.contains(receipt.source_repository.as_str()) {
            return fail(format!("receipt {} source repository is absent", receipt.receipt_id));
        }
        if !valid_repo_id(&receipt.execution_repository)
            || !is_sha(&receipt.source_commit)
            || !is_sha(&receipt.execution_commit)
            || !receipt.run_url.starts_with("https://github.com/")
        {
            return fail(format!("receipt {} has invalid source/execution identity", receipt.receipt_id));
        }
        if !matches!(receipt.status.as_str(), "passed" | "failed" | "blocked" | "missing-evidence") {
            return fail(format!("receipt {} has invalid status", receipt.receipt_id));
        }
        if !matches!(
            receipt.infrastructure_state.as_str(),
            "executed" | "zero-step" | "missing-credentials" | "unavailable-runner"
        ) {
            return fail(format!("receipt {} has invalid infrastructureState", receipt.receipt_id));
        }
        if receipt.status == "passed"
            && (receipt.infrastructure_state != "executed" || receipt.commands.is_empty())
        {
            return fail(format!(
                "receipt {} cannot pass unless commands actually executed",
                receipt.receipt_id
            ));
        }
        if receipt.infrastructure_state == "zero-step" && receipt.status == "passed" {
            return fail(format!("receipt {} zero-step is missing evidence, never pass", receipt.receipt_id));
        }
        for command in &receipt.commands {
            non_empty(command, "certification.commands")?;
        }
        for toolchain in &receipt.toolchains {
            non_empty(toolchain, "certification.toolchains")?;
        }
        for dep in &receipt.dependency_commits {
            if !valid_repo_id(&dep.repository) || !is_sha(&dep.commit) {
                return fail(format!("receipt {} has invalid dependency commit", receipt.receipt_id));
            }
        }
        for digest in &receipt.artifact_digests {
            if !is_digest(digest) {
                return fail(format!("receipt {} has invalid artifact digest", receipt.receipt_id));
            }
        }
        receipts.insert(receipt.receipt_id.as_str(), receipt);
    }

    let allowed_risks = ["S1", "S2", "S3", "V1", "V2", "L1", "M"];
    let mut claims = HashSet::new();
    for claim in &snapshot.formal_evidence {
        if claim.claim_id.trim().is_empty() || !claims.insert(claim.claim_id.as_str()) {
            return fail(format!("invalid or duplicate claimId {}", claim.claim_id));
        }
        if !repos.contains(claim.repository.as_str()) {
            return fail(format!("claim {} repository is absent", claim.claim_id));
        }
        if !matches!(claim.status.as_str(), "required" | "partial" | "verified" | "blocked") {
            return fail(format!("claim {} has invalid status", claim.claim_id));
        }
        if claim.risk_classes.is_empty()
            || claim.risk_classes.iter().any(|risk| !allowed_risks.contains(&risk.as_str()))
        {
            return fail(format!("claim {} has invalid riskClasses", claim.claim_id));
        }
        for (label, values) in [
            ("invariants", &claim.invariants),
            ("modelPaths", &claim.model_paths),
            ("implementationPaths", &claim.implementation_paths),
            ("testPaths", &claim.test_paths),
            ("assumptions", &claim.assumptions),
            ("bounds", &claim.bounds),
        ] {
            if values.is_empty() || values.iter().any(|v| v.trim().is_empty()) {
                return fail(format!("claim {} needs non-empty {label}", claim.claim_id));
            }
        }
        non_empty(&claim.broken_implementation_test, "brokenImplementationTest")?;
        if claim.status == "verified" {
            if claim.evidence_receipts.is_empty() {
                return fail(format!("verified claim {} needs evidence receipts", claim.claim_id));
            }
            for id in &claim.evidence_receipts {
                let Some(receipt) = receipts.get(id.as_str()) else {
                    return fail(format!("claim {} references unknown receipt {}", claim.claim_id, id));
                };
                if receipt.status != "passed" || receipt.source_repository != claim.repository {
                    return fail(format!(
                        "claim {} receipt {} must be passed evidence for the same repository",
                        claim.claim_id, id
                    ));
                }
            }
        }
    }
    Ok(())
}

fn load(path: &Path) -> Result<Snapshot, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn main() {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "governance/portfolio-governance.v1.json".to_owned());
    let path = Path::new(&path);
    match load(path).and_then(|snapshot| validate(&snapshot)) {
        Ok(()) => println!("portfolio governance validation: PASS {}", path.display()),
        Err(error) => {
            eprintln!("portfolio governance validation: FAIL: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_snapshot() -> Snapshot {
        serde_json::from_str(r#"{
          "schemaVersion":"ores.portfolio-governance.v1",
          "coverageState":"partial",
          "repositories":[{
            "id":"acme/runtime","observedCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "inspectionState":"reviewed","role":"runtime","languages":["rust"],
            "contractAuthorities":["runtime"],"releaseMechanism":"binary",
            "testRepositories":[],"deploymentConsumers":[],"dependencies":[]
          }],
          "certifications":[{
            "receiptId":"r1","sourceRepository":"acme/runtime",
            "sourceCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "executionRepository":"acme-test/runtime",
            "executionCommit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "runUrl":"https://github.com/acme-test/runtime/actions/runs/1",
            "status":"passed","infrastructureState":"executed",
            "commands":["cargo test"],"toolchains":["rust:stable"],
            "dependencyCommits":[],"artifactDigests":[]
          }],
          "formalEvidence":[{
            "claimId":"runtime-safety","repository":"acme/runtime","status":"verified",
            "riskClasses":["S1"],"invariants":["safe"],
            "modelPaths":["conformance/model.rs"],"implementationPaths":["src/lib.rs"],
            "testPaths":["tests/runtime.rs"],"assumptions":["bounded state"],
            "bounds":["one runtime"],"brokenImplementationTest":"tests/runtime.rs",
            "evidenceReceipts":["r1"]
          }]
        }"#).unwrap()
    }

    #[test]
    fn valid_snapshot_passes() {
        assert!(validate(&minimal_snapshot()).is_ok());
    }

    #[test]
    fn zero_step_can_never_be_passed() {
        let mut snapshot = minimal_snapshot();
        snapshot.certifications[0].infrastructure_state = "zero-step".into();
        assert!(validate(&snapshot).unwrap_err().contains("cannot pass"));
    }

    #[test]
    fn verified_claim_cannot_borrow_unrelated_receipt() {
        let mut snapshot = minimal_snapshot();
        snapshot.formal_evidence[0].repository = "acme/other".into();
        assert!(validate(&snapshot).is_err());
    }
}
