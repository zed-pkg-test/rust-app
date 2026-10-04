use crate::error::{OrmError, Result};
use crate::ir::{Column, OrmIr, OrmType, ScalarType, SourceKind, Table};
use quote::ToTokens;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Attribute, Ident, Item, Lit, Meta, Token, Type};

/// Parse one `diesel print-schema` style Rust source file.
pub fn parse_schema(source: &str) -> Result<OrmIr> {
    let file = syn::parse_file(source)?;
    let mut tables = Vec::new();
    collect_items(&file.items, &mut tables)?;
    if tables.is_empty() {
        return Err(OrmError::Invalid(
            "Diesel input contained no table! declarations".to_owned(),
        ));
    }
    return OrmIr::try_new(SourceKind::Diesel, tables);
}

fn collect_items(items: &[Item], tables: &mut Vec<Table>) -> Result<()> {
    for item in items {
        match item {
            Item::Macro(item_macro)
                if item_macro
                    .mac
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "table") =>
            {
                let parsed = syn::parse2::<DieselTable>(item_macro.mac.tokens.clone())?;
                tables.push(parsed.into_table()?);
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

#[derive(Debug)]
struct DieselColumn {
    attrs: Vec<Attribute>,
    name: Ident,
    ty: Type,
}

#[derive(Debug)]
struct DieselTable {
    attrs: Vec<Attribute>,
    schema_name: Option<Ident>,
    table_name: Ident,
    primary_key: Vec<Ident>,
    columns: Vec<DieselColumn>,
}

impl Parse for DieselTable {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        while input.peek(Token![use]) {
            let _: syn::ItemUse = input.parse()?;
        }

        let attrs = input.call(Attribute::parse_outer)?;
        let first: Ident = input.parse()?;
        let (schema_name, table_name) = if input.peek(Token![.]) {
            input.parse::<Token![.]>()?;
            (Some(first), input.parse()?)
        } else {
            (None, first)
        };

        let content;
        syn::parenthesized!(content in input);
        let primary_key = Punctuated::<Ident, Token![,]>::parse_terminated(&content)?
            .into_iter()
            .collect();

        let body;
        syn::braced!(body in input);
        let mut columns = Vec::new();
        while !body.is_empty() {
            let attrs = body.call(Attribute::parse_outer)?;
            let name: Ident = body.parse()?;
            body.parse::<Token![->]>()?;
            let ty: Type = body.parse()?;
            if body.peek(Token![,]) {
                body.parse::<Token![,]>()?;
            }
            columns.push(DieselColumn { attrs, name, ty });
        }

        if !input.is_empty() {
            return Err(input.error("unexpected tokens after Diesel table declaration"));
        }

        return Ok(Self {
            attrs,
            schema_name,
            table_name,
            primary_key,
            columns,
        });
    }
}

impl DieselTable {
    fn into_table(self) -> Result<Table> {
        let table_db_name = sql_name(&self.attrs)?.unwrap_or_else(|| self.table_name.to_string());
        let primary_keys: Vec<String> = self.primary_key.iter().map(ToString::to_string).collect();
        if primary_keys.is_empty() {
            return Err(OrmError::Invalid(format!(
                "Diesel table {table_db_name} declares an empty primary-key list"
            )));
        }
        for (index, key) in primary_keys.iter().enumerate() {
            if primary_keys[..index].contains(key) {
                return Err(OrmError::Invalid(format!(
                    "Diesel table {table_db_name} declares duplicate primary-key column {key}"
                )));
            }
        }

        let mut columns = Vec::with_capacity(self.columns.len());
        for (ordinal, column) in self.columns.into_iter().enumerate() {
            let rust_name = column.name.to_string();
            let db_name = sql_name(&column.attrs)?.unwrap_or_else(|| rust_name.clone());
            let (ty, nullable) = map_diesel_type(&column.ty)?;
            columns.push(Column {
                rust_name: rust_name.clone(),
                db_name,
                ordinal,
                ty,
                nullable,
                primary_key: primary_keys.iter().any(|key| key == &rust_name),
                unique: false,
            });
        }

        for key in &primary_keys {
            if !columns.iter().any(|column| column.rust_name == *key) {
                return Err(OrmError::Invalid(format!(
                    "Diesel table {table_db_name} primary-key column {key} is not declared in the table body"
                )));
            }
        }

        return Ok(Table {
            schema_name: self.schema_name.map(|ident| ident.to_string()),
            db_name: table_db_name,
            columns,
        });
    }
}

fn sql_name(attrs: &[Attribute]) -> Result<Option<String>> {
    for attr in attrs {
        if !attr.path().is_ident("sql_name") {
            continue;
        }
        match &attr.meta {
            Meta::NameValue(name_value) => {
                if let syn::Expr::Lit(expr_lit) = &name_value.value
                    && let Lit::Str(value) = &expr_lit.lit
                {
                    return Ok(Some(value.value()));
                }
                return Err(OrmError::Unsupported(
                    "Diesel #[sql_name] must contain a string literal".to_owned(),
                ));
            }
            _ => {
                return Err(OrmError::Unsupported(
                    "unsupported Diesel #[sql_name] syntax".to_owned(),
                ));
            }
        }
    }
    return Ok(None);
}

fn map_diesel_type(ty: &Type) -> Result<(OrmType, bool)> {
    let Type::Path(type_path) = ty else {
        return Err(OrmError::Unsupported(format!(
            "Diesel type is not a path: {}",
            ty.to_token_stream()
        )));
    };
    let segment =
        type_path.path.segments.last().ok_or_else(|| {
            OrmError::Unsupported("Diesel type path has no final segment".to_owned())
        })?;
    let name = segment.ident.to_string();

    if name == "Nullable" {
        let inner = single_generic_type(segment)?;
        let (inner, _) = map_diesel_type(inner)?;
        return Ok((inner, true));
    }
    if name == "Array" {
        let inner = single_generic_type(segment)?;
        let (inner, inner_nullable) = map_diesel_type(inner)?;
        if inner_nullable {
            return Err(OrmError::Unsupported(
                "nullable array elements require explicit contract evidence".to_owned(),
            ));
        }
        return Ok((OrmType::Array(Box::new(inner)), false));
    }

    let scalar = match name.as_str() {
        "Bool" => Some(ScalarType::Boolean),
        "SmallInt" | "Int2" => Some(ScalarType::Int16),
        "Integer" | "Int4" => Some(ScalarType::Int32),
        "BigInt" | "Int8" => Some(ScalarType::Int64),
        "Float" | "Float4" => Some(ScalarType::Float32),
        "Double" | "Float8" => Some(ScalarType::Float64),
        "Numeric" => Some(ScalarType::Decimal),
        "Text" | "Varchar" | "VarChar" | "Bpchar" | "Citext" => Some(ScalarType::String),
        "Uuid" => Some(ScalarType::Uuid),
        "Date" => Some(ScalarType::Date),
        "Timestamp" | "Timestamptz" => Some(ScalarType::DateTime),
        "Bytea" | "Binary" => Some(ScalarType::Bytes),
        "Json" | "Jsonb" => Some(ScalarType::Json),
        _ => None,
    };

    return Ok((
        scalar.map_or_else(|| OrmType::Named(name), OrmType::Scalar),
        false,
    ));
}

fn single_generic_type(segment: &syn::PathSegment) -> Result<&Type> {
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return Err(OrmError::Unsupported(format!(
            "{} requires one type argument",
            segment.ident
        )));
    };
    let mut types = arguments.args.iter().filter_map(|argument| match argument {
        syn::GenericArgument::Type(ty) => Some(ty),
        _ => None,
    });
    let first = types.next().ok_or_else(|| {
        OrmError::Unsupported(format!("{} requires one type argument", segment.ident))
    })?;
    if types.next().is_some() || arguments.args.len() != 1 {
        return Err(OrmError::Unsupported(format!(
            "{} accepts exactly one type argument in the ORM IR",
            segment.ident
        )));
    }
    return Ok(first);
}
