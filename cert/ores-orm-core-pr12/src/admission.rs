use crate::error::{OrmError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const TJSV_CONTRACT_IR_SCHEMA: &str = "ores.typespec-json-schema-validator.contract-ir/v1";
pub const TJSV_PARITY_REPORT_SCHEMA: &str = "ores.typespec-json-schema-validator.report/v1";
pub const TJSV_PROJECTION_MANIFEST_SCHEMA: &str =
    "ores.typespec-json-schema-validator.projection-manifest/v1";
pub const TJSV_PROJECTION_VERIFICATION_RECEIPT_SCHEMA: &str =
    "ores.typespec-json-schema-validator.projection-verification-receipt/v1";
pub const TJSV_ADMISSION_BINDING_SCHEMA: &str = "ores.orm-core.tjsv-admission-binding/v2";
pub const REQUIRED_PUBLIC_RUNTIME_VALIDATOR_IDS: &[&str] = &[
    "dart-json",
    "gleam-erlang",
    "gleam-js",
    "rust-serde",
    "typescript-zod",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TjsvOutputBinding {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TjsvAdmissionBinding {
    schema: String,
    projection_id: String,
    contract_ir_id: String,
    contract_ir_sha256: String,
    projection_manifest_id: String,
    projection_manifest_sha256: String,
    projection_verification_id: String,
    projection_verification_sha256: String,
    parity_receipt_run_id: String,
    evidence_digest: String,
    declaration_ids: Vec<String>,
    runtime_validator_ids: Vec<String>,
    outputs: Vec<TjsvOutputBinding>,
    #[serde(skip)]
    verified: bool,
}

impl TjsvAdmissionBinding {
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        return self.verified;
    }

    #[must_use]
    pub fn projection_id(&self) -> &str {
        return &self.projection_id;
    }

    #[must_use]
    pub fn contract_ir_sha256(&self) -> &str {
        return &self.contract_ir_sha256;
    }

    #[must_use]
    pub fn projection_manifest_sha256(&self) -> &str {
        return &self.projection_manifest_sha256;
    }

    #[must_use]
    pub fn projection_verification_sha256(&self) -> &str {
        return &self.projection_verification_sha256;
    }

    #[must_use]
    pub fn declaration_ids(&self) -> &[String] {
        return &self.declaration_ids;
    }

    #[must_use]
    pub fn runtime_validator_ids(&self) -> &[String] {
        return &self.runtime_validator_ids;
    }

    #[must_use]
    pub fn outputs(&self) -> &[TjsvOutputBinding] {
        return &self.outputs;
    }

    #[must_use]
    pub fn projection_manifest_id(&self) -> &str {
        return &self.projection_manifest_id;
    }

    #[must_use]
    pub fn projection_verification_id(&self) -> &str {
        return &self.projection_verification_id;
    }

    #[must_use]
    pub fn contract_ir_id(&self) -> &str {
        return &self.contract_ir_id;
    }

    #[must_use]
    pub fn parity_receipt_run_id(&self) -> &str {
        return &self.parity_receipt_run_id;
    }

    #[must_use]
    pub fn evidence_digest(&self) -> &str {
        return &self.evidence_digest;
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        return &self.schema;
    }

    pub fn verify(
        contract_ir_bytes: &[u8],
        projection_manifest_bytes: &[u8],
        projection_receipt_bytes: &[u8],
        expected_projection_id: &str,
        expected_declaration_ids: &[String],
    ) -> Result<Self> {
        if contract_ir_bytes.is_empty()
            || projection_manifest_bytes.is_empty()
            || projection_receipt_bytes.is_empty()
        {
            return Err(OrmError::Invalid(
                "TJSV admission requires non-empty Contract IR, projection manifest, and projection verification receipt bytes"
                    .to_owned(),
            ));
        }
        if !valid_identifier(expected_projection_id) {
            return Err(OrmError::Invalid(
                "expected TJSV projection id is not a valid projection identifier".to_owned(),
            ));
        }

        let expected_declarations =
            normalize_expected_ids(expected_declaration_ids, "expected declaration ids")?;
        let expected_runtime_validators = REQUIRED_PUBLIC_RUNTIME_VALIDATOR_IDS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();

        let contract_ir = parse_json(contract_ir_bytes, "Contract IR")?;
        let contract = contract_ir.as_object().ok_or_else(|| {
            OrmError::Invalid("TJSV Contract IR must be a JSON object".to_owned())
        })?;
        verify_contract_ir(contract, &contract_ir)?;

        let contract_ir_id = digest_field(contract, "irId", "Contract IR")?;
        let contract_ir_digest = canonical_digest(&contract_ir)?;
        let admission = object_field(contract, "admission", "Contract IR")?;
        let parity = object_field(admission, "receipt", "Contract IR admission")?;
        let parity_receipt_run_id = digest_field(parity, "runId", "Contract IR parity binding")?;
        let parity_receipt_digest = digest_field(parity, "digest", "Contract IR parity binding")?;
        let source_digests = contract_source_digests(contract)?;

        let projection_manifest = parse_json(projection_manifest_bytes, "projection manifest")?;
        let manifest = projection_manifest.as_object().ok_or_else(|| {
            OrmError::Invalid("TJSV projection manifest must be a JSON object".to_owned())
        })?;
        require_string(
            manifest,
            "schema",
            TJSV_PROJECTION_MANIFEST_SCHEMA,
            "projection manifest",
        )?;
        require_string(manifest, "status", "passed", "projection manifest")?;
        let projection_manifest_id = digest_field(manifest, "manifestId", "projection manifest")?;
        if canonical_digest_without(&projection_manifest, "manifestId")? != projection_manifest_id {
            return Err(OrmError::Invalid(
                "TJSV projection manifest self-digest does not match manifestId".to_owned(),
            ));
        }

        let manifest_contract = object_field(manifest, "contract", "projection manifest")?;
        require_digest_value(
            manifest_contract,
            "contractIrId",
            &contract_ir_id,
            "projection manifest contract",
        )?;
        require_digest_value(
            manifest_contract,
            "contractIrDigest",
            &contract_ir_digest,
            "projection manifest contract",
        )?;
        require_digest_value(
            manifest_contract,
            "receiptRunId",
            &parity_receipt_run_id,
            "projection manifest contract",
        )?;
        require_digest_value(
            manifest_contract,
            "receiptDigest",
            &parity_receipt_digest,
            "projection manifest contract",
        )?;
        verify_source_digests(
            object_field(
                manifest_contract,
                "sourceDigests",
                "projection manifest contract",
            )?,
            &source_digests,
            "projection manifest contract sourceDigests",
        )?;

        let manifest_declarations = normalize_ids(
            string_array_field(manifest, "declarations", "projection manifest")?,
            "projection manifest declarations",
            true,
        )?;
        for declaration_id in &expected_declarations {
            if !manifest_declarations.contains(declaration_id) {
                return Err(OrmError::Invalid(format!(
                    "TJSV projection manifest does not contain expected declaration {declaration_id}"
                )));
            }
        }

        let target = projection_target(manifest, expected_projection_id)?;
        let target_declarations = normalize_ids(
            string_array_field(target, "declarationIds", "projection target")?,
            "projection declaration ids",
            false,
        )?;
        if target_declarations != expected_declarations {
            return Err(OrmError::Invalid(format!(
                "TJSV projection declaration scope does not match expected scope: expected {expected_declarations:?}, got {target_declarations:?}"
            )));
        }

        let runtime_validator_ids = normalize_ids(
            string_array_field(target, "runtimeValidatorIds", "projection target")?,
            "projection runtime validator ids",
            false,
        )?;
        if runtime_validator_ids != expected_runtime_validators {
            return Err(OrmError::Invalid(format!(
                "TJSV projection runtime-validator scope does not match expected scope: expected {expected_runtime_validators:?}, got {runtime_validator_ids:?}"
            )));
        }

        verify_runtime_validators(manifest, expected_projection_id, &runtime_validator_ids)?;
        let outputs = projection_outputs(manifest, target, expected_projection_id)?;

        let projection_receipt =
            parse_json(projection_receipt_bytes, "projection verification receipt")?;
        let receipt = projection_receipt.as_object().ok_or_else(|| {
            OrmError::Invalid(
                "TJSV projection verification receipt must be a JSON object".to_owned(),
            )
        })?;
        require_string(
            receipt,
            "schema",
            TJSV_PROJECTION_VERIFICATION_RECEIPT_SCHEMA,
            "projection verification receipt",
        )?;
        require_string(
            receipt,
            "status",
            "passed",
            "projection verification receipt",
        )?;
        require_bool(
            receipt,
            "admissible",
            true,
            "projection verification receipt",
        )?;
        if receipt.get("failureCode") != Some(&Value::Null) {
            return Err(OrmError::Invalid(
                "passed TJSV projection verification receipt must have null failureCode".to_owned(),
            ));
        }
        let finding_rule_ids =
            string_array_field(receipt, "findingRuleIds", "projection verification receipt")?;
        if !finding_rule_ids.is_empty() {
            return Err(OrmError::Invalid(
                "passed TJSV projection verification receipt must not contain findings".to_owned(),
            ));
        }

        let projection_verification_id =
            digest_field(receipt, "verificationId", "projection verification receipt")?;
        if canonical_digest_without(&projection_receipt, "verificationId")?
            != projection_verification_id
        {
            return Err(OrmError::Invalid(
                "TJSV projection verification receipt self-digest does not match verificationId"
                    .to_owned(),
            ));
        }
        require_digest_value(
            receipt,
            "manifestId",
            &projection_manifest_id,
            "projection verification receipt",
        )?;
        require_digest_value(
            receipt,
            "contractIrId",
            &contract_ir_id,
            "projection verification receipt",
        )?;
        require_digest_value(
            receipt,
            "receiptRunId",
            &parity_receipt_run_id,
            "projection verification receipt",
        )?;
        let evidence_digest =
            digest_field(receipt, "evidenceDigest", "projection verification receipt")?;
        verify_source_digests(
            object_field(receipt, "sourceDigests", "projection verification receipt")?,
            &source_digests,
            "projection verification receipt sourceDigests",
        )?;
        verify_receipt_summary(receipt, manifest)?;

        return Ok(Self {
            schema: TJSV_ADMISSION_BINDING_SCHEMA.to_owned(),
            projection_id: expected_projection_id.to_owned(),
            contract_ir_id,
            contract_ir_sha256: digest(contract_ir_bytes),
            projection_manifest_id,
            projection_manifest_sha256: digest(projection_manifest_bytes),
            projection_verification_id,
            projection_verification_sha256: digest(projection_receipt_bytes),
            parity_receipt_run_id,
            evidence_digest,
            declaration_ids: expected_declarations,
            runtime_validator_ids,
            outputs,
            verified: true,
        });
    }
}

fn verify_contract_ir(
    contract: &serde_json::Map<String, Value>,
    contract_ir: &Value,
) -> Result<()> {
    require_string(contract, "schema", TJSV_CONTRACT_IR_SCHEMA, "Contract IR")?;
    require_string(contract, "status", "passed", "Contract IR")?;
    require_bool(contract, "admissible", true, "Contract IR")?;
    require_string(
        contract,
        "role",
        "downstream-derived-parity-artifact",
        "Contract IR",
    )?;
    require_bool(contract, "editableAuthority", false, "Contract IR")?;

    let authorities = object_field(contract, "authorities", "Contract IR")?;
    require_string(
        authorities,
        "typespec",
        "independently-authored",
        "Contract IR authorities",
    )?;
    require_string(
        authorities,
        "jsonSchema",
        "independently-authored",
        "Contract IR authorities",
    )?;
    require_string(
        authorities,
        "generatedJsonSchema",
        "comparison-evidence-only",
        "Contract IR authorities",
    )?;
    require_string(authorities, "precedence", "none", "Contract IR authorities")?;

    let contract_ir_id = digest_field(contract, "irId", "Contract IR")?;
    if canonical_digest_without(contract_ir, "irId")? != contract_ir_id {
        return Err(OrmError::Invalid(
            "TJSV Contract IR self-digest does not match irId".to_owned(),
        ));
    }

    let admission = object_field(contract, "admission", "Contract IR")?;
    let parity = object_field(admission, "receipt", "Contract IR admission")?;
    require_string(
        parity,
        "schema",
        TJSV_PARITY_REPORT_SCHEMA,
        "Contract IR parity binding",
    )?;
    require_string(parity, "status", "passed", "Contract IR parity binding")?;
    require_bool(
        parity,
        "zeroUnexplainedFindings",
        true,
        "Contract IR parity binding",
    )?;
    digest_field(parity, "runId", "Contract IR parity binding")?;
    digest_field(parity, "digest", "Contract IR parity binding")?;

    let requirements = object_field(admission, "requirements", "Contract IR admission")?;
    for key in [
        "exactInputDigests",
        "directDeclarationInventory",
        "generatedSchemaComparison",
        "differentialInstanceValidation",
        "zeroUnexplainedFindings",
    ] {
        require_bool(
            requirements,
            key,
            true,
            "Contract IR admission requirements",
        )?;
    }

    declaration_ids(contract)?;
    contract_source_digests(contract)?;
    return Ok(());
}

fn projection_target<'a>(
    manifest: &'a serde_json::Map<String, Value>,
    projection_id: &str,
) -> Result<&'a serde_json::Map<String, Value>> {
    let projections = manifest
        .get("projections")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            OrmError::Invalid("TJSV projection manifest projections must be an array".to_owned())
        })?;
    let mut matches = projections
        .iter()
        .filter_map(Value::as_object)
        .filter(|projection| projection.get("id").and_then(Value::as_str) == Some(projection_id));
    let target = matches.next().ok_or_else(|| {
        OrmError::Invalid(format!(
            "TJSV projection manifest is missing projection {projection_id}"
        ))
    })?;
    if matches.next().is_some() {
        return Err(OrmError::Invalid(format!(
            "TJSV projection manifest contains duplicate projection {projection_id}"
        )));
    }
    return Ok(target);
}

fn projection_outputs(
    manifest: &serde_json::Map<String, Value>,
    target: &serde_json::Map<String, Value>,
    projection_id: &str,
) -> Result<Vec<TjsvOutputBinding>> {
    let expected_paths = normalize_ids(
        string_array_field(target, "outputPaths", "projection target")?,
        "projection output paths",
        false,
    )?;
    if expected_paths.is_empty() {
        return Err(OrmError::Invalid(
            "admitted TJSV projection must contain at least one output".to_owned(),
        ));
    }

    let outputs = manifest
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            OrmError::Invalid("TJSV projection manifest outputs must be an array".to_owned())
        })?;
    let mut bindings = Vec::new();
    for output in outputs {
        let output = output.as_object().ok_or_else(|| {
            OrmError::Invalid("TJSV projection manifest output must be an object".to_owned())
        })?;
        if output.get("projection").and_then(Value::as_str) != Some(projection_id) {
            continue;
        }
        let path = nonempty_string_field(output, "path", "projection output")?;
        let sha256 = digest_field(output, "sha256", "projection output")?;
        bindings.push(TjsvOutputBinding { path, sha256 });
    }
    bindings.sort_by(|left, right| left.path.cmp(&right.path));
    let actual_paths = bindings
        .iter()
        .map(|binding| binding.path.clone())
        .collect::<Vec<_>>();
    if actual_paths != expected_paths {
        return Err(OrmError::Invalid(format!(
            "TJSV projection output closure does not match projection target: expected {expected_paths:?}, got {actual_paths:?}"
        )));
    }
    return Ok(bindings);
}

fn verify_runtime_validators(
    manifest: &serde_json::Map<String, Value>,
    projection_id: &str,
    expected_ids: &[String],
) -> Result<()> {
    let validators = manifest
        .get("runtimeValidators")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            OrmError::Invalid(
                "TJSV projection manifest runtimeValidators must be an array".to_owned(),
            )
        })?;
    let mut actual_ids = Vec::new();
    for validator in validators {
        let validator = validator.as_object().ok_or_else(|| {
            OrmError::Invalid("TJSV runtime validator must be an object".to_owned())
        })?;
        if validator.get("projection").and_then(Value::as_str) != Some(projection_id) {
            continue;
        }
        let id = nonempty_string_field(validator, "id", "runtime validator")?;
        if !valid_identifier(&id) {
            return Err(OrmError::Invalid(format!(
                "TJSV runtime validator id {id:?} is invalid"
            )));
        }
        digest_field(validator, "artifactDigest", "runtime validator")?;
        digest_field(validator, "fixtureDigest", "runtime validator")?;
        digest_field(
            validator,
            "ingressEgressCoverageDigest",
            "runtime validator",
        )?;
        nonempty_string_field(validator, "artifactPath", "runtime validator")?;
        actual_ids.push(id);
    }
    actual_ids = normalize_ids(actual_ids, "runtime validator manifest ids", false)?;
    if actual_ids != expected_ids {
        return Err(OrmError::Invalid(format!(
            "TJSV runtime-validator manifest entries do not match projection target: expected {expected_ids:?}, got {actual_ids:?}"
        )));
    }
    return Ok(());
}

fn verify_receipt_summary(
    receipt: &serde_json::Map<String, Value>,
    manifest: &serde_json::Map<String, Value>,
) -> Result<()> {
    let summary = object_field(receipt, "summary", "projection verification receipt")?;
    for (key, manifest_key) in [
        ("declarations", "declarations"),
        ("projections", "projections"),
        ("outputs", "outputs"),
        ("representationDeltas", "representationDeltas"),
        ("runtimeValidators", "runtimeValidators"),
    ] {
        let expected = manifest
            .get(manifest_key)
            .and_then(Value::as_array)
            .map(Vec::len)
            .ok_or_else(|| {
                OrmError::Invalid(format!(
                    "TJSV projection manifest {manifest_key} must be an array"
                ))
            })?;
        let actual = summary
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| {
                OrmError::Invalid(format!(
                    "TJSV projection verification summary {key} must be a non-negative integer"
                ))
            })?;
        if actual != expected {
            return Err(OrmError::Invalid(format!(
                "TJSV projection verification summary {key} does not match manifest: expected {expected}, got {actual}"
            )));
        }
    }
    return Ok(());
}

fn contract_source_digests(contract: &serde_json::Map<String, Value>) -> Result<[String; 3]> {
    let provenance = object_field(contract, "provenance", "Contract IR")?;
    let typespec = object_field(provenance, "typespec", "Contract IR provenance")?;
    let generated = object_field(provenance, "generatedJsonSchema", "Contract IR provenance")?;
    let authored = object_field(provenance, "authoredJsonSchema", "Contract IR provenance")?;
    return Ok([
        digest_field(typespec, "digest", "Contract IR TypeSpec provenance")?,
        digest_field(
            generated,
            "digest",
            "Contract IR generated JSON Schema provenance",
        )?,
        digest_field(
            authored,
            "digest",
            "Contract IR authored JSON Schema provenance",
        )?,
    ]);
}

fn verify_source_digests(
    object: &serde_json::Map<String, Value>,
    expected: &[String; 3],
    label: &str,
) -> Result<()> {
    for (index, key) in ["typespec", "generatedJsonSchema", "authoredJsonSchema"]
        .iter()
        .enumerate()
    {
        require_digest_value(object, key, &expected[index], label)?;
    }
    return Ok(());
}

fn parse_json(bytes: &[u8], label: &str) -> Result<Value> {
    return serde_json::from_slice(bytes)
        .map_err(|error| OrmError::Invalid(format!("could not parse TJSV {label}: {error}")));
}

fn require_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    expected: &str,
    label: &str,
) -> Result<()> {
    let actual = object.get(key).and_then(Value::as_str);
    if actual != Some(expected) {
        return Err(OrmError::Invalid(format!(
            "{label} {key} must be {expected:?}"
        )));
    }
    return Ok(());
}

fn require_bool(
    object: &serde_json::Map<String, Value>,
    key: &str,
    expected: bool,
    label: &str,
) -> Result<()> {
    let actual = object.get(key).and_then(Value::as_bool);
    if actual != Some(expected) {
        return Err(OrmError::Invalid(format!(
            "{label} {key} must be {expected}"
        )));
    }
    return Ok(());
}

fn require_digest_value(
    object: &serde_json::Map<String, Value>,
    key: &str,
    expected: &str,
    label: &str,
) -> Result<()> {
    let actual = digest_field(object, key, label)?;
    if actual != expected {
        return Err(OrmError::Invalid(format!(
            "{label} {key} does not match expected digest"
        )));
    }
    return Ok(());
}

fn object_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<&'a serde_json::Map<String, Value>> {
    return object
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| OrmError::Invalid(format!("{label} {key} must be a JSON object")));
}

fn nonempty_string_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<String> {
    return object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| OrmError::Invalid(format!("{label} {key} must be a non-empty string")));
}

fn digest_field(object: &serde_json::Map<String, Value>, key: &str, label: &str) -> Result<String> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| OrmError::Invalid(format!("{label} {key} must be a SHA-256 digest")))?;
    if !valid_digest(value) {
        return Err(OrmError::Invalid(format!(
            "{label} {key} must be a lowercase 64-character SHA-256 digest"
        )));
    }
    return Ok(value.to_owned());
}

fn string_array_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<Vec<String>> {
    let values = object
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| OrmError::Invalid(format!("{label} {key} must be an array")))?;
    return values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    OrmError::Invalid(format!("{label} {key} entries must be non-empty strings"))
                })
        })
        .collect();
}

fn declaration_ids(contract: &serde_json::Map<String, Value>) -> Result<BTreeSet<String>> {
    let declarations = contract
        .get("declarations")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            OrmError::Invalid("TJSV Contract IR declarations must be an array".to_owned())
        })?;
    let mut ids = BTreeSet::new();
    for declaration in declarations {
        let id = declaration
            .as_object()
            .and_then(|object| object.get("id"))
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                OrmError::Invalid(
                    "TJSV Contract IR declaration ids must be non-empty strings".to_owned(),
                )
            })?;
        if !ids.insert(id.to_owned()) {
            return Err(OrmError::Invalid(format!(
                "TJSV Contract IR contains duplicate declaration id {id}"
            )));
        }
    }
    return Ok(ids);
}

fn normalize_expected_ids(values: &[String], label: &str) -> Result<Vec<String>> {
    if values.is_empty() {
        return Err(OrmError::Invalid(format!(
            "TJSV admission requires at least one {label}"
        )));
    }
    return normalize_ids(values.to_vec(), label, false);
}

fn normalize_ids(mut values: Vec<String>, label: &str, allow_empty: bool) -> Result<Vec<String>> {
    if !allow_empty && values.is_empty() {
        return Err(OrmError::Invalid(format!("{label} must not be empty")));
    }
    if values.iter().any(|value| value.is_empty()) {
        return Err(OrmError::Invalid(format!(
            "{label} must not contain empty values"
        )));
    }
    values.sort();
    let original_len = values.len();
    values.dedup();
    if values.len() != original_len {
        return Err(OrmError::Invalid(format!(
            "{label} must not contain duplicates"
        )));
    }
    return Ok(values);
}

fn canonical_digest_without(value: &Value, excluded_key: &str) -> Result<String> {
    let mut value = value.clone();
    let object = value.as_object_mut().ok_or_else(|| {
        OrmError::Invalid("canonical TJSV evidence must be a JSON object".to_owned())
    })?;
    if object.remove(excluded_key).is_none() {
        return Err(OrmError::Invalid(format!(
            "canonical TJSV evidence is missing {excluded_key}"
        )));
    }
    return canonical_digest(&value);
}

fn canonical_digest(value: &Value) -> Result<String> {
    let canonical = canonical_json(value)?;
    return Ok(digest(canonical.as_bytes()));
}

fn canonical_json(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    return Ok(out);
}

fn write_canonical(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => out.push_str(&value.to_string()),
        Value::String(value) => {
            out.push_str(&serde_json::to_string(value).map_err(|error| {
                OrmError::Invalid(format!("could not canonicalize JSON string: {error}"))
            })?);
        }
        Value::Array(values) => {
            out.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(value, out)?;
            }
            out.push(']');
        }
        Value::Object(object) => {
            out.push('{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).map_err(|error| {
                    OrmError::Invalid(format!("could not canonicalize JSON object key: {error}"))
                })?);
                out.push(':');
                write_canonical(
                    object
                        .get(key.as_str())
                        .expect("canonical object key must exist"),
                    out,
                )?;
            }
            out.push('}');
        }
    }
    return Ok(());
}

fn valid_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if bytes.len() > 1
        && !bytes[bytes.len() - 1].is_ascii_lowercase()
        && !bytes[bytes.len() - 1].is_ascii_digit()
    {
        return false;
    }
    return bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'.' | b'_' | b'-')
    });
}

fn valid_digest(value: &str) -> bool {
    return value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
}

fn digest(bytes: &[u8]) -> String {
    return hex::encode(Sha256::digest(bytes));
}
