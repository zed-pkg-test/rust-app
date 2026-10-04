use ores_orm_core::diesel;
use ores_orm_core::emit::bundle::{
    self, ContractEvidenceState, GenerationEvidence, PublicationState,
};
use ores_orm_core::emit::json_schema;
use ores_orm_core::ir::{Column, OrmIr, OrmType, ScalarType, SourceKind, Table};
use ores_orm_core::parity;
use ores_orm_core::policy::{Policy, TablePolicy};
use ores_orm_core::seaorm;
use ores_orm_core::shapes::{Shape, ShapeField, ShapeKind, derive_shape};

const DIESEL: &str = include_str!("../fixtures/diesel/schema.rs");
const SEAORM: &str = include_str!("../fixtures/seaorm/users.rs");
const POLICY: &str = include_str!("../fixtures/ores-orm.toml");

fn witnesses() -> (OrmIr, OrmIr) {
    return (
        diesel::parse_schema(DIESEL).expect("Diesel fixture should parse"),
        seaorm::parse_source(SEAORM).expect("SeaORM fixture should parse"),
    );
}

fn converged() -> OrmIr {
    let (diesel, seaorm) = witnesses();
    return parity::converge(&diesel, &seaorm).expect("fixtures should converge");
}

fn evidence(ir: &OrmIr) -> GenerationEvidence {
    return GenerationEvidence::from_bytes(
        ir,
        &[
            ("fixtures/diesel/schema.rs", DIESEL.as_bytes()),
            ("fixtures/seaorm/users.rs", SEAORM.as_bytes()),
            ("fixtures/ores-orm.toml", POLICY.as_bytes()),
        ],
        b"audit-v2",
        None,
    )
    .expect("evidence");
}

fn empty_policy() -> Policy {
    Policy::from_toml("version = 1\nrequire_diesel = true\nrequire_seaorm = true\n")
        .expect("empty private policy")
}

fn private_ir(table_name: &str, fields: &[(&str, &str)]) -> OrmIr {
    let columns = fields
        .iter()
        .enumerate()
        .map(|(ordinal, (db_name, rust_name))| Column {
            rust_name: (*rust_name).to_owned(),
            db_name: (*db_name).to_owned(),
            ordinal,
            ty: OrmType::Scalar(ScalarType::String),
            nullable: false,
            primary_key: false,
            unique: false,
        })
        .collect();
    OrmIr::try_new(
        SourceKind::Converged,
        vec![Table {
            schema_name: None,
            db_name: table_name.to_owned(),
            columns,
        }],
    )
    .expect("synthetic private IR")
}

fn synthetic_evidence(ir: &OrmIr) -> GenerationEvidence {
    GenerationEvidence::from_bytes(ir, &[("synthetic", b"synthetic")], b"audit-v2", None)
        .expect("synthetic evidence")
}

#[test]
fn convergence_is_commutative_and_does_not_leak_source_only_unique_metadata() {
    let (diesel, seaorm) = witnesses();
    assert!(
        !diesel
            .table("users")
            .unwrap()
            .column("email")
            .unwrap()
            .unique
    );
    assert!(
        seaorm
            .table("users")
            .unwrap()
            .column("email")
            .unwrap()
            .unique
    );

    let diesel_first = parity::converge(&diesel, &seaorm).expect("converge");
    let seaorm_first = parity::converge(&seaorm, &diesel).expect("converge");
    assert_eq!(diesel_first, seaorm_first);
    assert!(
        !diesel_first
            .table("users")
            .unwrap()
            .column("email")
            .unwrap()
            .unique
    );
}

#[test]
fn ordinal_drift_is_a_blocking_parity_finding() {
    let (diesel, mut seaorm) = witnesses();
    let table = seaorm.tables.first_mut().expect("users table");
    table.columns.swap(1, 2);
    for (ordinal, column) in table.columns.iter_mut().enumerate() {
        column.ordinal = ordinal;
    }
    seaorm
        .validate()
        .expect("drifted witness remains structurally valid");

    let report = parity::compare(&diesel, &seaorm);
    assert!(!report.passed);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "column_ordinal_mismatch")
    );
}

#[test]
fn complete_policy_validation_rejects_orphan_table_entries() {
    let ir = converged();
    let mut policy = Policy::from_toml(POLICY).expect("policy");
    policy
        .table
        .insert("typo_users".to_owned(), TablePolicy::default());

    let error = policy
        .validate_ir(&ir)
        .expect_err("orphan policy entries must not be silently ignored");
    assert!(
        error
            .to_string()
            .contains("does not match any ORM IR table")
    );
}

#[test]
fn qualified_and_unqualified_policy_aliases_cannot_compete() {
    let mut ir = converged();
    ir.tables[0].schema_name = Some("public".to_owned());
    ir.validate().expect("schema-qualified IR");

    let mut policy = Policy::from_toml(POLICY).expect("policy");
    let users = policy.table.get("users").cloned().expect("users policy");
    policy.table.insert("public.users".to_owned(), users);

    let error = policy
        .validate_table(&ir.tables[0])
        .expect_err("policy aliases must not rely on hidden precedence");
    assert!(error.to_string().contains("both qualified key"));
}

#[test]
fn artifact_paths_are_safe_for_quoted_database_identifiers() {
    let ir = private_ir("../odd/table\\name", &[("body", "body")]);
    let policy = empty_policy();
    let shape = derive_shape(&ir.tables[0], &policy, ShapeKind::Row).expect("row shape");
    let bundle = bundle::emit(&ir, &policy, &shape, &synthetic_evidence(&ir))
        .expect("bundle should emit");

    for artifact in &bundle.artifacts {
        let mut parts = artifact.path.split('/');
        let directory = parts.next().expect("language directory");
        let filename = parts.next().expect("filename");
        assert!(
            parts.next().is_none(),
            "unexpected nested artifact path: {}",
            artifact.path
        );
        assert!(!directory.is_empty());
        assert!(!filename.contains(".."));
        assert!(!filename.contains('\\'));
        assert!(!filename.contains('/'));
    }

    let schema = json_schema::emit(&shape).expect("schema");
    let id = schema["$id"].as_str().expect("schema id");
    assert!(!id.contains("../"));
    assert_eq!(schema["x-ores-table"], "../odd/table\\name");
}

#[test]
fn source_identifiers_use_reversible_collision_free_escaping() {
    let ir = private_ir("collision_test", &[("a-b", "left"), ("a_b", "right")]);
    let policy = empty_policy();
    let shape = derive_shape(&ir.tables[0], &policy, ShapeKind::Row).expect("row shape");

    let bundle = bundle::emit(&ir, &policy, &shape, &synthetic_evidence(&ir))
        .expect("collision-safe bundle");
    let rust = bundle
        .artifacts
        .iter()
        .find(|artifact| artifact.path.starts_with("rust/"))
        .expect("Rust artifact");
    assert!(rust.content.contains("__ores_hex_612d62"));
    assert!(rust.content.contains("pub a_b:"));
}

#[test]
fn bundle_rejects_shape_not_derived_from_bound_ir_and_policy() {
    let ir = converged();
    let policy = Policy::from_toml(POLICY).expect("policy");
    let forged = Shape {
        table: "users".to_owned(),
        kind: ShapeKind::PublicCreate,
        fields: vec![ShapeField {
            db_name: "email".to_owned(),
            wire_name: "email".to_owned(),
            ty: OrmType::Scalar(ScalarType::String),
            nullable: false,
            required: true,
        }],
    };

    let error = bundle::emit(&ir, &policy, &forged, &evidence(&ir))
        .expect_err("forged subsets must not inherit unrelated ORM provenance");
    assert!(error.to_string().contains("does not match the exact shape"));
}

#[test]
fn bundle_rejects_evidence_from_different_ir() {
    let ir = converged();
    let policy = Policy::from_toml(POLICY).expect("policy");
    let shape = derive_shape(ir.table("users").unwrap(), &policy, ShapeKind::PublicCreate)
        .expect("shape");
    let other = private_ir("other", &[("body", "body")]);

    let error = bundle::emit(&ir, &policy, &shape, &synthetic_evidence(&other))
        .expect_err("evidence from another IR must be rejected");
    assert!(error.to_string().contains("does not match supplied ORM IR"));
}

#[test]
fn attached_contract_bytes_do_not_make_public_candidates_publishable() {
    let ir = converged();
    let policy = Policy::from_toml(POLICY).expect("policy");
    let shape = derive_shape(
        ir.table("users").expect("users"),
        &policy,
        ShapeKind::PublicCreate,
    )
    .expect("public create shape");
    let evidence = GenerationEvidence::from_bytes(
        &ir,
        &[
            ("fixtures/diesel/schema.rs", DIESEL.as_bytes()),
            ("fixtures/seaorm/users.rs", SEAORM.as_bytes()),
        ],
        b"audit-v2",
        Some((
            b"non-empty-unverified-contract-ir",
            b"non-empty-unverified-receipt",
        )),
    )
    .expect("digest binding is allowed");
    let bundle = bundle::emit(&ir, &policy, &shape, &evidence).expect("candidate bundle");

    assert_eq!(
        bundle.manifest.contract_evidence,
        ContractEvidenceState::EvidenceBound
    );
    assert_eq!(
        bundle.manifest.publication,
        PublicationState::BlockedPendingContractAdmission
    );
    assert!(!bundle.manifest.publishable());
}

#[test]
fn private_derivatives_remain_publishable_inside_the_backend_boundary() {
    let ir = private_ir("private_note", &[("body", "body")]);
    let policy = empty_policy();
    let shape = derive_shape(&ir.tables[0], &policy, ShapeKind::Row).expect("row shape");
    let bundle = bundle::emit(&ir, &policy, &shape, &synthetic_evidence(&ir))
        .expect("private bundle");

    assert_eq!(
        bundle.manifest.publication,
        PublicationState::PrivateDerivative
    );
    assert!(bundle.manifest.publishable());
}

#[test]
fn json_schema_enforces_int16_and_int32_domains_normatively() {
    let shape = Shape {
        table: "integer_bounds".to_owned(),
        kind: ShapeKind::Row,
        fields: vec![
            ShapeField {
                db_name: "small".to_owned(),
                wire_name: "small".to_owned(),
                ty: OrmType::Scalar(ScalarType::Int16),
                nullable: false,
                required: true,
            },
            ShapeField {
                db_name: "normal".to_owned(),
                wire_name: "normal".to_owned(),
                ty: OrmType::Scalar(ScalarType::Int32),
                nullable: false,
                required: true,
            },
        ],
    };
    let schema = json_schema::emit(&shape).expect("schema");

    assert_eq!(schema["properties"]["small"]["minimum"], -32768);
    assert_eq!(schema["properties"]["small"]["maximum"], 32767);
    assert_eq!(schema["properties"]["normal"]["minimum"], -2147483648_i64);
    assert_eq!(schema["properties"]["normal"]["maximum"], 2147483647_i64);
}
