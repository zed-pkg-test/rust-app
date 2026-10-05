use super::{dart, gleam, json_schema, naming, rust, typescript};
use crate::admission::TjsvAdmissionBinding;
use crate::error::{OrmError, Result};
use crate::ir::OrmIr;
use crate::policy::Policy;
use crate::shapes::{Shape, ShapeKind, derive_shape};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DERIVATIVE_MANIFEST_SCHEMA: &str = "ores.orm-core.derivative-manifest/v3";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractEvidenceState {
    NotApplicable,
    Required,
    /// Exact bytes have been digest-bound to the derivative. This does not
    /// mean TJSV has admitted the derivative for publication.
    EvidenceBound,
    /// The exact bound Contract IR and projection-verification receipt were
    /// independently verified before bundle promotion.
    Admitted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationState {
    PrivateDerivative,
    BlockedPendingContractAdmission,
    PublicAdmitted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputDigest {
    pub name: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractEvidenceDigest {
    pub contract_ir_sha256: String,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationEvidence {
    pub orm_ir_sha256: String,
    pub source_digests: Vec<InputDigest>,
    pub generator_options_sha256: String,
    pub contract: Option<ContractEvidenceDigest>,
}

impl GenerationEvidence {
    pub fn from_bytes(
        orm_ir: &OrmIr,
        source_inputs: &[(&str, &[u8])],
        generator_options: &[u8],
        contract: Option<(&[u8], &[u8])>,
    ) -> Result<Self> {
        orm_ir.validate()?;
        if source_inputs.is_empty() {
            return Err(OrmError::Invalid(
                "generation evidence requires at least one exact source input".to_owned(),
            ));
        }

        let mut source_digests = source_inputs
            .iter()
            .map(|(name, bytes)| {
                if name.trim().is_empty() {
                    return Err(OrmError::Invalid(
                        "generation evidence source names must not be empty".to_owned(),
                    ));
                }
                return Ok(InputDigest {
                    name: (*name).to_owned(),
                    sha256: digest(bytes),
                });
            })
            .collect::<Result<Vec<_>>>()?;
        source_digests.sort_by(|left, right| left.name.cmp(&right.name));
        for pair in source_digests.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(OrmError::Invalid(format!(
                    "generation evidence contains duplicate source name {}",
                    pair[0].name
                )));
            }
        }

        let ir_bytes = serde_json::to_vec(orm_ir)
            .map_err(|error| OrmError::Invalid(format!("could not encode ORM IR: {error}")))?;
        let contract = match contract {
            None => None,
            Some((contract_ir, receipt)) => {
                if contract_ir.is_empty() || receipt.is_empty() {
                    return Err(OrmError::Invalid(
                        "contract evidence requires non-empty Contract IR and receipt bytes"
                            .to_owned(),
                    ));
                }
                Some(ContractEvidenceDigest {
                    contract_ir_sha256: digest(contract_ir),
                    receipt_sha256: digest(receipt),
                })
            }
        };

        return Ok(Self {
            orm_ir_sha256: digest(&ir_bytes),
            source_digests,
            generator_options_sha256: digest(generator_options),
            contract,
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivativeManifest {
    pub schema: String,
    pub generator_version: String,
    pub table: String,
    pub shape: ShapeKind,
    pub projection_identity: String,
    pub public_candidate: bool,
    pub publication: PublicationState,
    pub contract_evidence: ContractEvidenceState,
    pub public_admission: Option<TjsvAdmissionBinding>,
    pub shape_sha256: String,
    /// SHA-256 of the deterministic JSON serialization of the exact validated
    /// `.ores-orm.toml` policy object used to derive this shape. This is kept
    /// separate from free-form generator options so provenance cannot claim one
    /// policy while emission actually used another.
    pub policy_sha256: String,
    pub evidence: GenerationEvidence,
    pub artifacts: Vec<ArtifactDigest>,
}

impl DerivativeManifest {
    #[must_use]
    pub fn publishable(&self) -> bool {
        return match self.publication {
            PublicationState::PrivateDerivative => true,
            PublicationState::BlockedPendingContractAdmission => false,
            PublicationState::PublicAdmitted => self
                .public_admission
                .as_ref()
                .is_some_and(TjsvAdmissionBinding::is_verified),
        };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedArtifact {
    pub path: String,
    pub sha256: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedBundle {
    pub manifest: DerivativeManifest,
    pub artifacts: Vec<GeneratedArtifact>,
}

impl GeneratedBundle {
    pub fn manifest_json(&self) -> Result<String> {
        return serde_json::to_string_pretty(&self.manifest)
            .map_err(|error| OrmError::Invalid(format!("could not encode manifest: {error}")));
    }
}

/// Emit a derivative only after proving that the supplied shape is exactly the
/// shape derived from the same converged ORM IR and policy bound to this run.
pub fn emit(
    orm_ir: &OrmIr,
    policy: &Policy,
    shape: &Shape,
    evidence: &GenerationEvidence,
) -> Result<GeneratedBundle> {
    return emit_with_admission(orm_ir, policy, shape, evidence, None);
}

pub fn emit_admitted(
    orm_ir: &OrmIr,
    policy: &Policy,
    shape: &Shape,
    evidence: &GenerationEvidence,
    admission: &TjsvAdmissionBinding,
) -> Result<GeneratedBundle> {
    if !shape.kind.is_public() {
        return Err(OrmError::Invalid(
            "TJSV public admission can only be attached to public ORM shapes".to_owned(),
        ));
    }
    if !admission.is_verified() {
        return Err(OrmError::Invalid(
            "TJSV public admission binding must be verified in this process before promotion"
                .to_owned(),
        ));
    }

    let contract = evidence.contract.as_ref().ok_or_else(|| {
        OrmError::Invalid(
            "admitted public ORM bundle requires exact Contract IR and projection-verification receipt bytes in generation evidence"
                .to_owned(),
        )
    })?;
    if contract.contract_ir_sha256.as_str() != admission.contract_ir_sha256() {
        return Err(OrmError::Invalid(
            "TJSV admission Contract IR digest does not match generation evidence".to_owned(),
        ));
    }
    if contract.receipt_sha256.as_str() != admission.projection_verification_sha256() {
        return Err(OrmError::Invalid(
            "TJSV projection-verification receipt digest does not match generation evidence"
                .to_owned(),
        ));
    }

    let expected_projection_id = naming::projection_id(shape);
    if admission.projection_id() != expected_projection_id.as_str() {
        return Err(OrmError::Invalid(format!(
            "TJSV admission projection id {} does not match generated projection {expected_projection_id}",
            admission.projection_id()
        )));
    }

    return emit_with_admission(orm_ir, policy, shape, evidence, Some(admission.clone()));
}

fn emit_with_admission(
    orm_ir: &OrmIr,
    policy: &Policy,
    shape: &Shape,
    evidence: &GenerationEvidence,
    admission: Option<TjsvAdmissionBinding>,
) -> Result<GeneratedBundle> {
    orm_ir.validate()?;
    policy.validate_ir(orm_ir)?;
    shape.validate()?;

    let ir_bytes = serde_json::to_vec(orm_ir)
        .map_err(|error| OrmError::Invalid(format!("could not encode ORM IR: {error}")))?;
    let actual_ir_sha256 = digest(&ir_bytes);
    if evidence.orm_ir_sha256 != actual_ir_sha256 {
        return Err(OrmError::Invalid(format!(
            "generation evidence ORM IR digest {} does not match supplied ORM IR {}",
            evidence.orm_ir_sha256, actual_ir_sha256
        )));
    }

    let policy_bytes = serde_json::to_vec(policy)
        .map_err(|error| OrmError::Invalid(format!("could not encode ORM policy: {error}")))?;
    let policy_sha256 = digest(&policy_bytes);

    let table = orm_ir.table(&shape.table).ok_or_else(|| {
        OrmError::Invalid(format!(
            "derived shape references table {} that is absent from the bound ORM IR",
            shape.table
        ))
    })?;
    let expected = derive_shape(table, policy, shape.kind)?;
    if &expected != shape {
        return Err(OrmError::Invalid(format!(
            "supplied {:?} shape for {} does not match the exact shape derived from the bound ORM IR and policy",
            shape.kind, shape.table
        )));
    }

    naming::validate_identifiers(shape, &[], "generated")?;

    let stem = naming::safe_artifact_stem(shape);
    let schema = serde_json::to_string_pretty(&json_schema::emit(shape)?)
        .map_err(|error| OrmError::Invalid(format!("could not encode JSON Schema: {error}")))?;

    let sources = [
        (format!("rust/{stem}.rs"), rust::emit(shape)?),
        (format!("typescript/{stem}.ts"), typescript::emit(shape)?),
        (format!("dart/{stem}.dart"), dart::emit(shape)?),
        (format!("gleam/{stem}.gleam"), gleam::emit(shape)?),
        (format!("json-schema/{stem}.schema.json"), schema),
    ];

    let artifacts = sources
        .into_iter()
        .map(|(path, content)| GeneratedArtifact {
            sha256: digest(content.as_bytes()),
            path,
            content,
        })
        .collect::<Vec<_>>();

    if let Some(admission) = admission.as_ref() {
        let mut actual = artifacts
            .iter()
            .map(|artifact| (artifact.path.clone(), artifact.sha256.clone()))
            .collect::<Vec<_>>();
        actual.sort();
        let mut expected = admission
            .outputs()
            .iter()
            .map(|output| (output.path.clone(), output.sha256.clone()))
            .collect::<Vec<_>>();
        expected.sort();
        if actual != expected {
            return Err(OrmError::Invalid(format!(
                "TJSV verified output closure does not match generated bundle: expected {expected:?}, got {actual:?}"
            )));
        }
    }

    let artifact_digests = artifacts
        .iter()
        .map(|artifact| ArtifactDigest {
            path: artifact.path.clone(),
            sha256: artifact.sha256.clone(),
        })
        .collect();
    let shape_bytes = serde_json::to_vec(shape)
        .map_err(|error| OrmError::Invalid(format!("could not encode shape: {error}")))?;
    let contract_evidence = match (
        shape.kind.is_public(),
        evidence.contract.is_some(),
        admission.is_some(),
    ) {
        (false, _, false) => ContractEvidenceState::NotApplicable,
        (false, _, true) => {
            return Err(OrmError::Invalid(
                "private ORM bundle cannot carry public TJSV admission".to_owned(),
            ));
        }
        (true, false, false) => ContractEvidenceState::Required,
        (true, true, false) => ContractEvidenceState::EvidenceBound,
        (true, true, true) => ContractEvidenceState::Admitted,
        (true, false, true) => {
            return Err(OrmError::Invalid(
                "public TJSV admission requires bound contract evidence".to_owned(),
            ));
        }
    };
    let publication = match (shape.kind.is_public(), admission.is_some()) {
        (false, false) => PublicationState::PrivateDerivative,
        (false, true) => {
            return Err(OrmError::Invalid(
                "private ORM bundle cannot be promoted through public TJSV admission".to_owned(),
            ));
        }
        (true, false) => PublicationState::BlockedPendingContractAdmission,
        (true, true) => PublicationState::PublicAdmitted,
    };

    return Ok(GeneratedBundle {
        manifest: DerivativeManifest {
            schema: DERIVATIVE_MANIFEST_SCHEMA.to_owned(),
            generator_version: env!("CARGO_PKG_VERSION").to_owned(),
            table: shape.table.clone(),
            shape: shape.kind,
            projection_identity: naming::projection_id(shape),
            public_candidate: shape.kind.is_public(),
            publication,
            contract_evidence,
            public_admission: admission,
            shape_sha256: digest(&shape_bytes),
            policy_sha256,
            evidence: evidence.clone(),
            artifacts: artifact_digests,
        },
        artifacts,
    });
}

fn digest(bytes: &[u8]) -> String {
    return hex::encode(Sha256::digest(bytes));
}
