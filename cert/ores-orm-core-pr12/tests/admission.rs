use ores_orm_core::diesel;
use ores_orm_core::emit::bundle::{
    self, ContractEvidenceState, DerivativeManifest, GeneratedBundle, GenerationEvidence,
    PublicationState,
};
use ores_orm_core::parity;
use ores_orm_core::policy::Policy;
use ores_orm_core::seaorm;
use ores_orm_core::shapes::{ShapeKind, derive_shape};
use ores_orm_core::{REQUIRED_PUBLIC_RUNTIME_VALIDATOR_IDS, TjsvAdmissionBinding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DIESEL: &str = include_str!("../fixtures/diesel/schema.rs");
const SEAORM: &str = include_str!("../fixtures/seaorm/users.rs");
const POLICY: &str = include_str!("../fixtures/ores-orm.toml");

const DECLARATION: &str = "Example.Accounts.Users.PublicCreate";
fn digest(bytes: &[u8]) -> String {
    return hex::encode(Sha256::digest(bytes));
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("JSON string"),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            let entries = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("JSON key"),
                        canonical_json(object.get(key).expect("canonical key"))
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{entries}}}")
        }
    }
}

fn canonical_digest(value: &Value) -> String {
    return digest(canonical_json(value).as_bytes());
}

fn converged() -> ores_orm_core::OrmIr {
    let diesel = diesel::parse_schema(DIESEL).expect("Diesel fixture should parse");
    let seaorm = seaorm::parse_source(SEAORM).expect("SeaORM fixture should parse");
    return parity::converge(&diesel, &seaorm).expect("fixtures should converge");
}

fn public_create_candidate() -> (
    ores_orm_core::OrmIr,
    Policy,
    ores_orm_core::Shape,
    GeneratedBundle,
) {
    let ir = converged();
    let policy = Policy::from_toml(POLICY).expect("policy");
    let shape = derive_shape(
        ir.table("users").expect("users"),
        &policy,
        ShapeKind::PublicCreate,
    )
    .expect("public create");
    let evidence = GenerationEvidence::from_bytes(
        &ir,
        &[
            ("fixtures/diesel/schema.rs", DIESEL.as_bytes()),
            ("fixtures/seaorm/users.rs", SEAORM.as_bytes()),
            ("fixtures/ores-orm.toml", POLICY.as_bytes()),
        ],
        b"admission-v2",
        None,
    )
    .expect("candidate evidence");
    let candidate = bundle::emit(&ir, &policy, &shape, &evidence).expect("candidate bundle");
    return (ir, policy, shape, candidate);
}

fn media_type(path: &str) -> &'static str {
    if path.starts_with("rust/") {
        return "text/x-rust";
    }
    if path.starts_with("typescript/") {
        return "application/typescript";
    }
    if path.starts_with("dart/") {
        return "text/x-dart";
    }
    if path.starts_with("gleam/") {
        return "text/x-gleam";
    }
    return "application/schema+json";
}

fn artifact<'a>(
    candidate: &'a GeneratedBundle,
    prefix: &str,
) -> &'a ores_orm_core::emit::bundle::GeneratedArtifact {
    return candidate
        .artifacts
        .iter()
        .find(|artifact| artifact.path.starts_with(prefix))
        .expect("language artifact");
}

fn tjsv_fixture(candidate: &GeneratedBundle) -> (Vec<u8>, Vec<u8>, Vec<u8>, TjsvAdmissionBinding) {
    let projection_id = candidate.manifest.projection_identity.clone();
    let run_id = "a".repeat(64);
    let parity_digest = "b".repeat(64);
    let typespec_digest = "c".repeat(64);
    let generated_schema_digest = "d".repeat(64);
    let authored_schema_digest = "e".repeat(64);

    let mut contract = json!({
        "schema": "ores.typespec-json-schema-validator.contract-ir/v1",
        "status": "passed",
        "admissible": true,
        "role": "downstream-derived-parity-artifact",
        "editableAuthority": false,
        "authorities": {
            "typespec": "independently-authored",
            "jsonSchema": "independently-authored",
            "generatedJsonSchema": "comparison-evidence-only",
            "precedence": "none"
        },
        "admission": {
            "receipt": {
                "schema": "ores.typespec-json-schema-validator.report/v1",
                "runId": run_id.clone(),
                "digest": parity_digest.clone(),
                "status": "passed",
                "zeroUnexplainedFindings": true
            },
            "requirements": {
                "exactInputDigests": true,
                "directDeclarationInventory": true,
                "generatedSchemaComparison": true,
                "differentialInstanceValidation": true,
                "zeroUnexplainedFindings": true
            }
        },
        "provenance": {
            "typespec": {
                "role": "independently-authored-authority",
                "digest": typespec_digest.clone(),
                "files": []
            },
            "generatedJsonSchema": {
                "role": "comparison-evidence-only",
                "digest": generated_schema_digest.clone(),
                "files": []
            },
            "authoredJsonSchema": {
                "role": "independently-authored-authority",
                "digest": authored_schema_digest.clone(),
                "files": []
            }
        },
        "declarations": [{
            "id": DECLARATION,
            "kind": "model"
        }],
        "excludedDeclarations": [],
        "outOfScopeDeclarations": []
    });
    let ir_id = canonical_digest(&contract);
    contract
        .as_object_mut()
        .expect("contract object")
        .insert("irId".to_owned(), Value::String(ir_id.clone()));
    let contract_digest = canonical_digest(&contract);

    let outputs = candidate
        .artifacts
        .iter()
        .map(|artifact| {
            json!({
                "path": artifact.path.clone(),
                "sha256": artifact.sha256.clone(),
                "size": artifact.content.len(),
                "mediaType": media_type(&artifact.path),
                "projection": projection_id.clone()
            })
        })
        .collect::<Vec<_>>();
    let output_paths = candidate
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();

    let rust = artifact(candidate, "rust/");
    let typescript = artifact(candidate, "typescript/");
    let dart = artifact(candidate, "dart/");
    let gleam = artifact(candidate, "gleam/");
    let runtime_validators = vec![
        json!({
            "id": "rust-serde",
            "projection": projection_id.clone(),
            "artifactPath": rust.path.clone(),
            "artifactDigest": rust.sha256.clone(),
            "fixtureDigest": "1".repeat(64),
            "ingressEgressCoverageDigest": "6".repeat(64)
        }),
        json!({
            "id": "typescript-zod",
            "projection": projection_id.clone(),
            "artifactPath": typescript.path.clone(),
            "artifactDigest": typescript.sha256.clone(),
            "fixtureDigest": "2".repeat(64),
            "ingressEgressCoverageDigest": "7".repeat(64)
        }),
        json!({
            "id": "dart-json",
            "projection": projection_id.clone(),
            "artifactPath": dart.path.clone(),
            "artifactDigest": dart.sha256.clone(),
            "fixtureDigest": "3".repeat(64),
            "ingressEgressCoverageDigest": "8".repeat(64)
        }),
        json!({
            "id": "gleam-erlang",
            "projection": projection_id.clone(),
            "artifactPath": gleam.path.clone(),
            "artifactDigest": gleam.sha256.clone(),
            "fixtureDigest": "4".repeat(64),
            "ingressEgressCoverageDigest": "9".repeat(64)
        }),
        json!({
            "id": "gleam-js",
            "projection": projection_id.clone(),
            "artifactPath": gleam.path.clone(),
            "artifactDigest": gleam.sha256.clone(),
            "fixtureDigest": "5".repeat(64),
            "ingressEgressCoverageDigest": "0".repeat(64)
        }),
    ];

    let mut manifest = json!({
        "schema": "ores.typespec-json-schema-validator.projection-manifest/v1",
        "status": "passed",
        "contract": {
            "contractIrId": ir_id.clone(),
            "contractIrDigest": contract_digest,
            "receiptRunId": run_id.clone(),
            "receiptDigest": parity_digest,
            "sourceDigests": {
                "typespec": typespec_digest.clone(),
                "generatedJsonSchema": generated_schema_digest.clone(),
                "authoredJsonSchema": authored_schema_digest.clone()
            }
        },
        "inputs": {
            "operationInventory": {
                "path": "projection/operations.json",
                "sha256": "1".repeat(64),
                "size": 1
            },
            "projectionMetadata": {
                "path": "projection/metadata.json",
                "sha256": "2".repeat(64),
                "size": 1
            },
            "emitterConfiguration": {
                "path": "projection/emitter.json",
                "sha256": "3".repeat(64),
                "size": 1
            }
        },
        "toolchains": [{
            "id": "ores-orm-core",
            "version": env!("CARGO_PKG_VERSION"),
            "artifactDigest": "f".repeat(64)
        }],
        "declarations": [DECLARATION],
        "projections": [{
            "id": projection_id,
            "emitter": "ores-orm-core",
            "declarationIds": [DECLARATION],
            "outputPaths": output_paths,
            "representationDeltaIds": [],
            "runtimeValidatorIds": REQUIRED_PUBLIC_RUNTIME_VALIDATOR_IDS
        }],
        "outputs": outputs,
        "representationDeltas": [],
        "runtimeValidators": runtime_validators
    });
    let manifest_id = canonical_digest(&manifest);
    manifest
        .as_object_mut()
        .expect("manifest object")
        .insert("manifestId".to_owned(), Value::String(manifest_id.clone()));

    let mut receipt = json!({
        "schema": "ores.typespec-json-schema-validator.projection-verification-receipt/v1",
        "status": "passed",
        "admissible": true,
        "manifestId": manifest_id,
        "contractIrId": ir_id,
        "receiptRunId": run_id,
        "evidenceDigest": "f".repeat(64),
        "sourceDigests": {
            "typespec": typespec_digest,
            "generatedJsonSchema": generated_schema_digest,
            "authoredJsonSchema": authored_schema_digest
        },
        "summary": {
            "declarations": 1,
            "projections": 1,
            "outputs": candidate.artifacts.len(),
            "representationDeltas": 0,
            "runtimeValidators": REQUIRED_PUBLIC_RUNTIME_VALIDATOR_IDS.len()
        },
        "findingRuleIds": [],
        "failureCode": null
    });
    let verification_id = canonical_digest(&receipt);
    receipt
        .as_object_mut()
        .expect("receipt object")
        .insert("verificationId".to_owned(), Value::String(verification_id));

    let contract_bytes = serde_json::to_vec(&contract).expect("contract bytes");
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest bytes");
    let receipt_bytes = serde_json::to_vec(&receipt).expect("receipt bytes");
    let declarations = vec![DECLARATION.to_owned()];
    let binding = TjsvAdmissionBinding::verify(
        &contract_bytes,
        &manifest_bytes,
        &receipt_bytes,
        &candidate.manifest.projection_identity,
        &declarations,
    )
    .expect("fixture should verify");

    return (contract_bytes, manifest_bytes, receipt_bytes, binding);
}

#[test]
fn verified_projection_receipt_is_required_for_public_promotion() {
    let (ir, policy, shape, candidate) = public_create_candidate();
    let (contract_ir, _manifest, projection_receipt, admission) = tjsv_fixture(&candidate);
    let evidence = GenerationEvidence::from_bytes(
        &ir,
        &[
            ("fixtures/diesel/schema.rs", DIESEL.as_bytes()),
            ("fixtures/seaorm/users.rs", SEAORM.as_bytes()),
            ("fixtures/ores-orm.toml", POLICY.as_bytes()),
        ],
        b"admission-v2",
        Some((&contract_ir, &projection_receipt)),
    )
    .expect("generation evidence");

    let bound = bundle::emit(&ir, &policy, &shape, &evidence).expect("bound candidate");
    assert_eq!(
        bound.manifest.contract_evidence,
        ContractEvidenceState::EvidenceBound
    );
    assert_eq!(
        bound.manifest.publication,
        PublicationState::BlockedPendingContractAdmission
    );
    assert!(!bound.manifest.publishable());

    let admitted = bundle::emit_admitted(&ir, &policy, &shape, &evidence, &admission)
        .expect("admitted bundle");
    assert_eq!(
        admitted.manifest.contract_evidence,
        ContractEvidenceState::Admitted
    );
    assert_eq!(
        admitted.manifest.publication,
        PublicationState::PublicAdmitted
    );
    assert!(admitted.manifest.publishable());
    assert_eq!(
        admitted.manifest.projection_identity,
        admission.projection_id()
    );
    assert_eq!(admission.declaration_ids(), &[DECLARATION.to_owned()]);
    assert_eq!(admission.runtime_validator_ids().len(), 5);
    assert_eq!(admission.outputs().len(), 5);
}

#[test]
fn projection_admission_rejects_wrong_scope_and_tampered_receipt() {
    let (_ir, _policy, _shape, candidate) = public_create_candidate();
    let (contract_ir, manifest, receipt, _) = tjsv_fixture(&candidate);
    assert!(
        TjsvAdmissionBinding::verify(
            &contract_ir,
            &manifest,
            &receipt,
            "orm.bad.public_create",
            &[DECLARATION.to_owned()],
        )
        .is_err()
    );

    let mut tampered: Value = serde_json::from_slice(&receipt).expect("receipt JSON");
    tampered["summary"]["runtimeValidators"] = json!(4);
    let tampered = serde_json::to_vec(&tampered).expect("tampered receipt");
    assert!(
        TjsvAdmissionBinding::verify(
            &contract_ir,
            &manifest,
            &tampered,
            &candidate.manifest.projection_identity,
            &[DECLARATION.to_owned()],
        )
        .is_err()
    );
}

#[test]
fn admitted_bundle_requires_exact_verified_output_and_receipt_bytes() {
    let (ir, policy, shape, candidate) = public_create_candidate();
    let (contract_ir, _manifest, receipt, admission) = tjsv_fixture(&candidate);

    let altered_receipt = [receipt.as_slice(), b"\n"].concat();
    let mismatched_evidence = GenerationEvidence::from_bytes(
        &ir,
        &[("fixtures/diesel/schema.rs", DIESEL.as_bytes())],
        b"admission-v2",
        Some((&contract_ir, &altered_receipt)),
    )
    .expect("digest binding accepts exact supplied bytes");
    assert!(bundle::emit_admitted(&shape, &mismatched_evidence, &admission).is_err());

    let evidence = GenerationEvidence::from_bytes(
        &ir,
        &[("fixtures/diesel/schema.rs", DIESEL.as_bytes())],
        b"admission-v2",
        Some((&contract_ir, &receipt)),
    )
    .expect("evidence");
    let admitted = bundle::emit_admitted(&ir, &policy, &shape, &evidence, &admission)
        .expect("admitted bundle");

    let serialized =
        serde_json::to_string(&admitted.manifest).expect("serialize admitted manifest");
    let replayed: DerivativeManifest =
        serde_json::from_str(&serialized).expect("deserialize manifest");
    assert!(
        !replayed.publishable(),
        "deserialization must clear the in-process verified capability"
    );
}
