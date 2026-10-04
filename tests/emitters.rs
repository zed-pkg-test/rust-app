use ores_orm_core::descriptor::{DescriptorSource, OrmWitness, describe_table};
use ores_orm_core::diesel;
use ores_orm_core::emit::bundle::{ContractEvidenceState, GenerationEvidence};
use ores_orm_core::emit::{bundle, dart, gleam, rust, typescript};
use ores_orm_core::ir::{OrmType, ScalarType};
use ores_orm_core::parity;
use ores_orm_core::policy::{FieldVisibility, Policy};
use ores_orm_core::seaorm;
use ores_orm_core::shapes::{Shape, ShapeField, ShapeKind, derive_shape};

const DIESEL: &str = include_str!("../fixtures/diesel/schema.rs");
const SEAORM: &str = include_str!("../fixtures/seaorm/users.rs");
const POLICY: &str = include_str!("../fixtures/ores-orm.toml");

fn converged() -> ores_orm_core::OrmIr {
    let diesel = diesel::parse_schema(DIESEL).expect("Diesel fixture should parse");
    let seaorm = seaorm::parse_source(SEAORM).expect("SeaORM fixture should parse");

    return parity::converge(&diesel, &seaorm).expect("ORM fixtures should converge");
}

fn generation_evidence(ir: &ores_orm_core::OrmIr) -> GenerationEvidence {
    return GenerationEvidence::from_bytes(
        ir,
        &[
            ("fixtures/diesel/schema.rs", DIESEL.as_bytes()),
            ("fixtures/seaorm/users.rs", SEAORM.as_bytes()),
            ("fixtures/ores-orm.toml", POLICY.as_bytes()),
        ],
        b"shape-policy-v1",
        None,
    )
    .expect("generation evidence should be deterministic");
}

#[test]
fn descriptor_keeps_secret_storage_out_of_public_shapes() {
    let ir = converged();
    let policy = Policy::from_toml(POLICY).expect("policy should parse");
    let table = ir.table("users").expect("users table");
    let source = DescriptorSource::new(
        "ORESoftware/example-orm-core",
        "0123456789abcdef0123456789abcdef01234567",
        "example-orm-core",
        "rustc 1.88.0",
        vec![OrmWitness::Diesel, OrmWitness::SeaOrm],
    )
    .expect("source should validate");
    let descriptor =
        describe_table(table, &policy, "Example.Accounts", source).expect("descriptor should emit");

    let password = descriptor
        .model
        .fields
        .iter()
        .find(|field| field.database_name == "password_hash")
        .expect("secret field");
    assert_eq!(password.visibility, FieldVisibility::Secret);
    assert!(descriptor.model.public_surface);

    let public_read =
        derive_shape(table, &policy, ShapeKind::PublicRead).expect("public read shape");
    assert!(
        public_read
            .fields
            .iter()
            .all(|field| field.db_name != "password_hash")
    );
}

#[test]
fn public_surface_rejects_unclassified_columns() {
    let ir = converged();
    let mut policy = Policy::from_toml(POLICY).expect("policy should parse");
    policy
        .table
        .get_mut("users")
        .expect("users policy")
        .secret
        .clear();

    let table = ir.table("users").expect("users table");
    let error = derive_shape(table, &policy, ShapeKind::PublicRead)
        .expect_err("unclassified public table field must fail");

    assert!(error.to_string().contains("password_hash"));
    assert!(error.to_string().contains("unclassified"));
}

#[test]
fn language_emitters_preserve_optional_nullable_and_closed_object_semantics() {
    let ir = converged();
    let policy = Policy::from_toml(POLICY).expect("policy should parse");
    let table = ir.table("users").expect("users table");
    let shape = derive_shape(table, &policy, ShapeKind::PublicCreate).expect("public create shape");

    let rust = rust::emit(&shape).expect("Rust should emit");
    assert!(rust.contains("#[serde(deny_unknown_fields)]"));
    assert!(rust.contains("pub display_name: Option<Option<String>>"));
    assert!(rust.contains("deserialize_optional_nullable"));
    assert!(rust.contains("Canonical JSON Schema is emitted as a sibling artifact"));
    assert!(!rust.contains("schemars::JsonSchema"));
    assert!(!rust.contains("password_hash"));
    syn::parse_file(&rust).expect("generated Rust should parse as a Rust source file");

    let typescript = typescript::emit(&shape).expect("TypeScript should emit");
    assert!(typescript.contains("z.object({"));
    assert!(typescript.contains("}).strict()"));
    assert!(typescript.contains("\"display_name\": z.string().nullable().optional()"));
    assert!(!typescript.contains("password_hash"));

    let dart = dart::emit(&shape).expect("Dart should emit");
    assert!(dart.contains("OresOptional<String?> display_name"));
    assert!(dart.contains("final OresOptional<String?> display_nameValue"));
    assert!(dart.contains("unknownKeys"));
    assert!(dart.contains("missing required field: email"));
    assert!(!dart.contains("password_hash"));

    let gleam = gleam::emit(&shape).expect("Gleam should emit");
    assert!(gleam.contains("display_name: Presence(Option(String))"));
    assert!(gleam.contains("import gleam/option.{type Option}"));
    assert!(gleam.contains("decode.dict(decode.string, decode.dynamic)"));
    assert!(gleam.contains("closed object"));
    assert!(!gleam.contains("password_hash"));
}

#[test]
fn bundle_is_deterministic_and_digest_bound() {
    let ir = converged();
    let policy = Policy::from_toml(POLICY).expect("policy should parse");
    let table = ir.table("users").expect("users table");
    let shape = derive_shape(table, &policy, ShapeKind::PublicCreate).expect("public create shape");

    let evidence = generation_evidence(&ir);
    let first = bundle::emit(&ir, &policy, &shape, &evidence).expect("bundle should emit");
    let second = bundle::emit(&ir, &policy, &shape, &evidence)
        .expect("bundle should emit deterministically");

    assert_eq!(first, second);
    assert_eq!(first.artifacts.len(), 5);
    assert!(first.manifest.public_candidate);
    assert_eq!(
        first.manifest.contract_evidence,
        ContractEvidenceState::Required
    );
    assert_eq!(first.manifest.generator_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(first.manifest.evidence.source_digests.len(), 3);
    assert_eq!(first.manifest.evidence.orm_ir_sha256.len(), 64);
    assert_eq!(first.manifest.evidence.generator_options_sha256.len(), 64);
    assert_eq!(first.manifest.artifacts.len(), 5);
    assert!(
        first
            .manifest
            .artifacts
            .iter()
            .all(|artifact| artifact.sha256.len() == 64)
    );
    assert_eq!(
        first.manifest_json().expect("manifest JSON"),
        second.manifest_json().expect("manifest JSON")
    );
}

#[test]
fn unsafe_cross_target_numeric_domains_fail_closed() {
    let shape = Shape {
        table: "example".to_owned(),
        kind: ShapeKind::PublicRead,
        fields: vec![ShapeField {
            db_name: "counter".to_owned(),
            wire_name: "counter".to_owned(),
            ty: OrmType::Scalar(ScalarType::Int64),
            nullable: false,
            required: true,
        }],
    };

    assert!(typescript::emit(&shape).is_err());
    assert!(dart::emit(&shape).is_err());
    assert!(gleam::emit(&shape).is_err());
    let ir = converged();
    let policy = Policy::from_toml(POLICY).expect("policy");
    let evidence = generation_evidence(&ir);
    assert!(bundle::emit(&ir, &policy, &shape, &evidence).is_err());
    assert!(rust::emit(&shape).is_err());
    assert!(ores_orm_core::emit::json_schema::emit(&shape).is_err());
}

#[test]
fn descriptor_source_fails_closed_on_invalid_provenance() {
    assert!(
        DescriptorSource::new(
            "",
            "0123456789abcdef0123456789abcdef01234567",
            "example-orm-core",
            "rustc 1.88.0",
            vec![OrmWitness::Diesel],
        )
        .is_err()
    );
    assert!(
        DescriptorSource::new(
            "ORESoftware/example-orm-core",
            "not-a-revision",
            "example-orm-core",
            "rustc 1.88.0",
            vec![OrmWitness::Diesel],
        )
        .is_err()
    );
    assert!(
        DescriptorSource::new(
            "ORESoftware/example-orm-core",
            "0123456789abcdef0123456789abcdef01234567",
            "example-orm-core",
            "rustc 1.88.0",
            vec![OrmWitness::Diesel, OrmWitness::Diesel],
        )
        .is_err()
    );
}

#[test]
fn patch_emitters_reject_empty_objects() {
    let ir = converged();
    let policy = Policy::from_toml(POLICY).expect("policy should parse");
    let table = ir.table("users").expect("users table");
    let shape = derive_shape(table, &policy, ShapeKind::PublicPatch).expect("public patch shape");

    let schema = ores_orm_core::emit::json_schema::emit(&shape).expect("JSON Schema should emit");
    assert_eq!(schema["minProperties"], 1);

    let rust = rust::emit(&shape).expect("Rust should emit");
    assert!(rust.contains("patch must contain at least one field"));
    assert!(rust.contains("pub fn validate(&self)"));

    let typescript = typescript::emit(&shape).expect("TypeScript should emit");
    assert!(typescript.contains("Object.keys(value).length > 0"));

    let dart = dart::emit(&shape).expect("Dart should emit");
    assert!(dart.contains("if (json.isEmpty)"));
    assert!(dart.contains("patch must contain at least one field"));

    let gleam = gleam::emit(&shape).expect("Gleam should emit");
    assert!(gleam.contains("dict.size(fields)"));
    assert!(gleam.contains("non-empty patch object"));
}

#[test]
fn dart_uuid_validation_accepts_all_hex_version_nibbles() {
    let shape = Shape {
        table: "example".to_owned(),
        kind: ShapeKind::PublicRead,
        fields: vec![ShapeField {
            db_name: "id".to_owned(),
            wire_name: "id".to_owned(),
            ty: OrmType::Scalar(ScalarType::Uuid),
            nullable: false,
            required: true,
        }],
    };

    let source = dart::emit(&shape).expect("Dart should emit");
    assert!(source.contains("[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"));
    assert!(!source.contains("[1-5][0-9a-fA-F]{3}"));
}

#[test]
fn public_bundle_records_bound_contract_evidence_without_claiming_admission() {
    let ir = converged();
    let policy = Policy::from_toml(POLICY).expect("policy should parse");
    let table = ir.table("users").expect("users table");
    let shape = derive_shape(table, &policy, ShapeKind::PublicCreate).expect("public create shape");
    let evidence = GenerationEvidence::from_bytes(
        &ir,
        &[
            ("fixtures/diesel/schema.rs", DIESEL.as_bytes()),
            ("fixtures/seaorm/users.rs", SEAORM.as_bytes()),
            ("fixtures/ores-orm.toml", POLICY.as_bytes()),
        ],
        b"shape-policy-v1",
        Some((b"exact-tjsv-contract-ir", b"exact-tjsv-receipt")),
    )
    .expect("bound evidence");

    let bundle = bundle::emit(&ir, &policy, &shape, &evidence).expect("bundle should emit");
    assert_eq!(
        bundle.manifest.contract_evidence,
        ContractEvidenceState::EvidenceBound
    );
    let contract = bundle
        .manifest
        .evidence
        .contract
        .as_ref()
        .expect("contract evidence");
    assert_eq!(contract.contract_ir_sha256.len(), 64);
    assert_eq!(contract.receipt_sha256.len(), 64);
}
