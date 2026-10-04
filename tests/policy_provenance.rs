use ores_orm_core::emit::bundle::{self, GenerationEvidence};
use ores_orm_core::ir::{Column, OrmIr, OrmType, ScalarType, SourceKind, Table};
use ores_orm_core::policy::Policy;
use ores_orm_core::shapes::{ShapeKind, derive_shape};

fn private_ir() -> OrmIr {
    OrmIr::try_new(
        SourceKind::Converged,
        vec![Table {
            schema_name: None,
            db_name: "notes".to_owned(),
            columns: vec![Column {
                rust_name: "body".to_owned(),
                db_name: "body".to_owned(),
                ordinal: 0,
                ty: OrmType::Scalar(ScalarType::String),
                nullable: false,
                primary_key: false,
                unique: false,
            }],
        }],
    )
    .expect("synthetic converged IR")
}

fn evidence(ir: &OrmIr) -> GenerationEvidence {
    GenerationEvidence::from_bytes(
        ir,
        &[("synthetic/diesel.rs", b"table! notes")],
        b"same-generator-options",
        None,
    )
    .expect("generation evidence")
}

#[test]
fn derivative_manifest_binds_the_exact_validated_policy_independently_of_options() {
    let ir = private_ir();
    let policy_a = Policy::from_toml(
        "version = 1\nrequire_diesel = true\nrequire_seaorm = true\n",
    )
    .expect("policy a");
    let policy_b = Policy::from_toml(
        "version = 1\nrequire_diesel = false\nrequire_seaorm = true\n",
    )
    .expect("policy b");

    // This private row shape is intentionally identical under both policies.
    // Provenance still must distinguish which exact policy was supplied to the
    // emitter, even when the caller reuses identical generator-options bytes.
    let shape_a = derive_shape(&ir.tables[0], &policy_a, ShapeKind::Row).expect("shape a");
    let shape_b = derive_shape(&ir.tables[0], &policy_b, ShapeKind::Row).expect("shape b");
    assert_eq!(shape_a, shape_b);

    let evidence = evidence(&ir);
    let bundle_a = bundle::emit(&ir, &policy_a, &shape_a, &evidence).expect("bundle a");
    let bundle_b = bundle::emit(&ir, &policy_b, &shape_b, &evidence).expect("bundle b");

    assert_eq!(
        bundle_a.manifest.evidence.generator_options_sha256,
        bundle_b.manifest.evidence.generator_options_sha256
    );
    assert_ne!(
        bundle_a.manifest.policy_sha256,
        bundle_b.manifest.policy_sha256,
        "policy provenance must not collapse merely because the derived shape is unchanged"
    );
    assert_eq!(
        bundle_a.manifest.schema,
        "ores.orm-core.derivative-manifest/v3"
    );
}
