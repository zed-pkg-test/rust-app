use ores_orm_core::diesel;
use ores_orm_core::emit::bundle::{self, GenerationEvidence};
use ores_orm_core::parity;
use ores_orm_core::policy::Policy;
use ores_orm_core::seaorm;
use ores_orm_core::shapes::{ShapeKind, derive_shape};
use std::fs;
use std::path::{Path, PathBuf};

const DIESEL: &str = include_str!("../fixtures/diesel/schema.rs");
const SEAORM: &str = include_str!("../fixtures/seaorm/users.rs");
const POLICY: &str = include_str!("../fixtures/ores-orm.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::var_os("ORES_ORM_RUNTIME_FIXTURE_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::other("ORES_ORM_RUNTIME_FIXTURE_DIR is required"))?;

    let diesel_ir = diesel::parse_schema(DIESEL)?;
    let seaorm_ir = seaorm::parse_source(SEAORM)?;
    let ir = parity::converge(&diesel_ir, &seaorm_ir)?;
    let policy = Policy::from_toml(POLICY)?;
    policy.validate_ir(&ir)?;
    let table = ir
        .table("users")
        .ok_or_else(|| std::io::Error::other("users table missing"))?;
    let shape = derive_shape(table, &policy, ShapeKind::PublicCreate)?;
    let evidence = GenerationEvidence::from_bytes(
        &ir,
        &[
            ("fixtures/diesel/schema.rs", DIESEL.as_bytes()),
            ("fixtures/seaorm/users.rs", SEAORM.as_bytes()),
            ("fixtures/ores-orm.toml", POLICY.as_bytes()),
        ],
        b"runtime-fixture-public-create-v1",
        None,
    )?;
    let generated = bundle::emit(&ir, &policy, &shape, &evidence)?;

    if output.exists() {
        fs::remove_dir_all(&output)?;
    }
    fs::create_dir_all(&output)?;
    for artifact in &generated.artifacts {
        let destination = safe_destination(&output, &artifact.path)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(destination, artifact.content.as_bytes())?;
    }
    fs::write(output.join("manifest.json"), generated.manifest_json()?)?;
    Ok(())
}

fn safe_destination(root: &Path, relative: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(std::io::Error::other(format!(
            "unsafe generated artifact path: {relative}"
        ))
        .into());
    }
    Ok(root.join(path))
}
