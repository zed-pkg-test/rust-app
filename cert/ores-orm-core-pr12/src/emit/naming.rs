use crate::error::{OrmError, Result};
use crate::shapes::{Shape, ShapeKind};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const ESCAPED_IDENTIFIER_PREFIX: &str = "__ores_hex_";

pub(crate) fn type_name(shape: &Shape) -> String {
    // Keep a readable prefix while including the complete table identity. The
    // full UTF-8 hex suffix prevents `a-b`, `a_b`, `a.b`, and similarly
    // normalized names from silently producing the same exported type.
    return format!(
        "{}T{}{}",
        pascal(&shape.table.replace('.', "_")),
        hex::encode(shape.table.as_bytes()),
        shape_suffix(shape.kind)
    );
}

pub(crate) fn projection_id(shape: &Shape) -> String {
    let table_digest = hex::encode(Sha256::digest(shape.table.as_bytes()));
    return format!("orm.{table_digest}.{}", shape_slug(shape.kind));
}

pub(crate) fn safe_artifact_stem(shape: &Shape) -> String {
    // Database identifiers may legally contain path separators, `..`, spaces,
    // or punctuation when quoted. Never interpolate them directly into output
    // paths. Hex encoding is reversible, deterministic, and collision-free for
    // the exact UTF-8 table identity.
    return format!(
        "table_{}_{}",
        hex::encode(shape.table.as_bytes()),
        shape_slug(shape.kind)
    );
}

pub(crate) fn validate_identifiers(shape: &Shape, reserved: &[&str], language: &str) -> Result<()> {
    let mut seen = BTreeMap::<String, String>::new();
    for field in &shape.fields {
        let generated = identifier(&field.db_name, reserved);
        if let Some(previous) = seen.insert(generated.clone(), field.db_name.clone()) {
            return Err(OrmError::Invalid(format!(
                "{language} identifier {generated:?} collides for database fields {previous:?} and {:?}; add an explicit non-colliding mapping before generation",
                field.db_name
            )));
        }
    }
    return Ok(());
}

pub(crate) const fn shape_slug(kind: ShapeKind) -> &'static str {
    return match kind {
        ShapeKind::Row => "row",
        ShapeKind::Create => "create",
        ShapeKind::Update => "update",
        ShapeKind::Patch => "patch",
        ShapeKind::PublicRead => "public_read",
        ShapeKind::PublicCreate => "public_create",
        ShapeKind::PublicUpdate => "public_update",
        ShapeKind::PublicPatch => "public_patch",
    };
}

pub(crate) const fn shape_suffix(kind: ShapeKind) -> &'static str {
    return match kind {
        ShapeKind::Row => "Row",
        ShapeKind::Create => "Create",
        ShapeKind::Update => "Update",
        ShapeKind::Patch => "Patch",
        ShapeKind::PublicRead => "PublicRead",
        ShapeKind::PublicCreate => "PublicCreate",
        ShapeKind::PublicUpdate => "PublicUpdate",
        ShapeKind::PublicPatch => "PublicPatch",
    };
}

pub(crate) fn pascal(value: &str) -> String {
    let mut out = String::new();
    let mut upper = true;

    for ch in value.chars() {
        if !ch.is_ascii_alphanumeric() {
            upper = true;
            continue;
        }

        if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }

    if out.is_empty() {
        return "Generated".to_owned();
    }
    if out.as_bytes()[0].is_ascii_digit() {
        return format!("Generated{out}");
    }

    return out;
}

pub(crate) fn identifier(value: &str, reserved: &[&str]) -> String {
    let bytes = value.as_bytes();
    let starts_valid = bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_');
    let all_valid = bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    let can_preserve = !value.is_empty()
        && starts_valid
        && all_valid
        && !reserved.contains(&value)
        && !value.starts_with(ESCAPED_IDENTIFIER_PREFIX);

    if can_preserve {
        return value.to_owned();
    }

    // The escape prefix itself is reserved from pass-through above, so an
    // authored identifier can never collide with this reversible encoding.
    return format!(
        "{ESCAPED_IDENTIFIER_PREFIX}{}",
        hex::encode(value.as_bytes())
    );
}
