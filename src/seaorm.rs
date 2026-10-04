use crate::error::{OrmError, Result};
use crate::ir::{Column, OrmIr, OrmType, ScalarType, SourceKind, Table};
use quote::ToTokens;
use std::path::Path;
use syn::{Attribute, Fields, GenericArgument, Item, ItemStruct, LitStr, PathArguments, Type};
use walkdir::WalkDir;

/// Parse one Rust source file containing one or more SeaORM entities.
pub fn parse_source(source: &str) -> Result<OrmIr> {
    let file = syn::parse_file(source)?;
    let mut tables = Vec::new();
    collect_items(&file.items, &mut tables)?;
    if tables.is_empty() {
        return Err(OrmError::Invalid(
            "SeaORM input contained no DeriveEntityModel models".to_owned(),
        ));
    }
    return OrmIr::try_new(SourceKind::SeaOrm, tables);
}

/// Parse every `.rs` file under a generated/entity source directory.
pub fn parse_directory(root: impl AsRef<Path>) -> Result<OrmIr> {
    let mut tables = Vec::new();
    for entry in WalkDir::new(root) {
        let entry = entry.map_err(|error| OrmError::Io(std::io::Error::other(error)))?;
        if !entry.file_type().is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("rs")
        {
            continue;
        }
        let source = std::fs::read_to_string(entry.path())?;
        let file = syn::parse_file(&source)?;
        collect_items(&file.items, &mut tables)?;
    }
    if tables.is_empty() {
        return Err(OrmError::Invalid(
            "SeaORM directory contained no DeriveEntityModel models".to_owned(),
        ));
    }
    return OrmIr::try_new(SourceKind::SeaOrm, tables);
}

fn collect_items(items: &[Item], tables: &mut Vec<Table>) -> Result<()> {
    for item in items {
        match item {
            Item::Struct(item_struct) if is_entity_model(item_struct) => {
                tables.push(parse_model(item_struct)?);
            }
            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_items(nested, tables)?;
                }
            }
            _ => {}
        }
    }
    return Ok(());
}

fn is_entity_model(item: &ItemStruct) -> bool {
    return item.attrs.iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }
        let mut found = false;
        let _ = attr.parse_nested_meta(|meta| {
            if meta
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "DeriveEntityModel")
            {
                found = true;
            }
            return Ok(());
        });
        return found;
    });
}

fn parse_model(item: &ItemStruct) -> Result<Table> {
    let options = sea_orm_options(&item.attrs)?;
    ensure_supported_options(&options, &format!("SeaORM model {}", item.ident))?;
    if options.ignore {
        return Err(OrmError::Unsupported(format!(
            "SeaORM model {} cannot use #[sea_orm(ignore)]",
            item.ident
        )));
    }

    let table_name = options.table_name.ok_or_else(|| {
        OrmError::Invalid(format!(
            "SeaORM model {} has no #[sea_orm(table_name = ...)]",
            item.ident
        ))
    })?;
    let Fields::Named(fields) = &item.fields else {
        return Err(OrmError::Unsupported(format!(
            "SeaORM model {} is not a named-field struct",
            item.ident
        )));
    };

    let mut columns = Vec::new();
    for field in &fields.named {
        let Some(ident) = &field.ident else {
            continue;
        };
        if is_relation_type(&field.ty) {
            continue;
        }
        let field_options = sea_orm_options(&field.attrs)?;
        if field_options.ignore {
            continue;
        }
        ensure_supported_options(
            &field_options,
            &format!("SeaORM field {}.{}", item.ident, ident),
        )?;

        let rust_name = ident.to_string();
        let db_name = field_options
            .column_name
            .clone()
            .unwrap_or_else(|| rust_name.clone());
        let (inner_type, nullable) = unwrap_option(&field.ty)?;
        if field_options.nullable && !nullable {
            return Err(OrmError::Unsupported(format!(
                "SeaORM field {}.{} uses #[sea_orm(nullable)] without Option<T>; explicit nullability mapping is required",
                item.ident, ident
            )));
        }
        let ty = map_rust_type(inner_type)?;
        columns.push(Column {
            rust_name,
            db_name,
            ordinal: columns.len(),
            ty,
            nullable,
            primary_key: field_options.primary_key,
            unique: field_options.unique,
        });
    }

    return Ok(Table {
        schema_name: options.schema_name,
        db_name: table_name,
        columns,
    });
}

#[derive(Default)]
struct SeaOrmOptions {
    table_name: Option<String>,
    schema_name: Option<String>,
    column_name: Option<String>,
    primary_key: bool,
    unique: bool,
    ignore: bool,
    nullable: bool,
    unsupported_semantic_overrides: Vec<String>,
}

fn sea_orm_options(attrs: &[Attribute]) -> Result<SeaOrmOptions> {
    let mut options = SeaOrmOptions::default();
    for attr in attrs {
        if !attr.path().is_ident("sea_orm") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("primary_key") {
                options.primary_key = true;
                return Ok(());
            }
            if meta.path.is_ident("unique") {
                options.unique = true;
                return Ok(());
            }
            if meta.path.is_ident("ignore") {
                options.ignore = true;
                return Ok(());
            }
            if meta.path.is_ident("nullable") {
                options.nullable = true;
                return Ok(());
            }
            if meta.path.is_ident("indexed") {
                return Ok(());
            }
            if meta.path.is_ident("table_name") {
                options.table_name = Some(meta.value()?.parse::<LitStr>()?.value());
                return Ok(());
            }
            if meta.path.is_ident("schema_name") {
                options.schema_name = Some(meta.value()?.parse::<LitStr>()?.value());
                return Ok(());
            }
            if meta.path.is_ident("column_name") {
                options.column_name = Some(meta.value()?.parse::<LitStr>()?.value());
                return Ok(());
            }
            if meta.path.is_ident("column_type")
                || meta.path.is_ident("select_as")
                || meta.path.is_ident("save_as")
            {
                let name = meta.path.to_token_stream().to_string().replace(' ', "");
                let _ = meta.value()?.parse::<syn::Expr>()?;
                options.unsupported_semantic_overrides.push(name);
                return Ok(());
            }
            if meta.path.is_ident("auto_increment")
                || meta.path.is_ident("default_value")
                || meta.path.is_ident("default_expr")
                || meta.path.is_ident("comment")
            {
                if meta.input.peek(syn::Token![=]) {
                    let _ = meta.value()?.parse::<syn::Expr>()?;
                }
                return Ok(());
            }

            return Err(meta.error(
                "unsupported SeaORM #[sea_orm(...)] option; add explicit ORM IR semantics before accepting it",
            ));
        })?;
    }
    return Ok(options);
}

fn ensure_supported_options(options: &SeaOrmOptions, context: &str) -> Result<()> {
    if options.unsupported_semantic_overrides.is_empty() {
        return Ok(());
    }

    return Err(OrmError::Unsupported(format!(
        "{context} uses SeaORM semantic override(s) {} that can change database type behavior; explicit mapping is required",
        options.unsupported_semantic_overrides.join(", ")
    )));
}

fn is_relation_type(ty: &Type) -> bool {
    let Type::Path(path) = ty else {
        return false;
    };
    return path
        .path
        .segments
        .last()
        .is_some_and(|segment| matches!(segment.ident.to_string().as_str(), "HasOne" | "HasMany"));
}

fn unwrap_option(ty: &Type) -> Result<(&Type, bool)> {
    let Type::Path(path) = ty else {
        return Ok((ty, false));
    };
    let Some(segment) = path.path.segments.last() else {
        return Ok((ty, false));
    };
    if segment.ident != "Option" {
        return Ok((ty, false));
    }
    let inner = single_generic_type(segment)?;
    return Ok((inner, true));
}

fn map_rust_type(ty: &Type) -> Result<OrmType> {
    let Type::Path(path) = ty else {
        return Err(OrmError::Unsupported(format!(
            "SeaORM field type is not a path: {}",
            ty.to_token_stream()
        )));
    };
    let segment = path.path.segments.last().ok_or_else(|| {
        OrmError::Unsupported("SeaORM field type path has no final segment".to_owned())
    })?;
    let name = segment.ident.to_string();

    if name == "Vec" {
        let inner = single_generic_type(segment)?;
        let (inner, element_nullable) = unwrap_option(inner)?;
        if element_nullable {
            return Err(OrmError::Unsupported(
                "nullable SeaORM array elements require explicit contract evidence".to_owned(),
            ));
        }
        if matches!(inner, Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "u8"))
        {
            return Ok(OrmType::Scalar(ScalarType::Bytes));
        }
        return Ok(OrmType::Array(Box::new(map_rust_type(inner)?)));
    }

    let scalar = match name.as_str() {
        "bool" => Some(ScalarType::Boolean),
        "i16" => Some(ScalarType::Int16),
        "i32" => Some(ScalarType::Int32),
        "i64" => Some(ScalarType::Int64),
        "f32" => Some(ScalarType::Float32),
        "f64" => Some(ScalarType::Float64),
        "Decimal" | "BigDecimal" => Some(ScalarType::Decimal),
        "String" => Some(ScalarType::String),
        "Uuid" => Some(ScalarType::Uuid),
        "Date" | "NaiveDate" => Some(ScalarType::Date),
        "DateTime" | "DateTimeUtc" | "DateTimeWithTimeZone" | "NaiveDateTime"
        | "OffsetDateTime" | "PrimitiveDateTime" => Some(ScalarType::DateTime),
        "Json" | "JsonValue" | "Value" => Some(ScalarType::Json),
        _ => None,
    };

    return Ok(scalar.map_or_else(
        || OrmType::Named(path.path.to_token_stream().to_string().replace(' ', "")),
        OrmType::Scalar,
    ));
}

fn single_generic_type(segment: &syn::PathSegment) -> Result<&Type> {
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return Err(OrmError::Unsupported(format!(
            "{} requires exactly one type argument",
            segment.ident
        )));
    };
    if arguments.args.len() != 1 {
        return Err(OrmError::Unsupported(format!(
            "{} requires exactly one type argument",
            segment.ident
        )));
    }
    let Some(GenericArgument::Type(inner)) = arguments.args.first() else {
        return Err(OrmError::Unsupported(format!(
            "{} requires exactly one type argument",
            segment.ident
        )));
    };
    return Ok(inner);
}
