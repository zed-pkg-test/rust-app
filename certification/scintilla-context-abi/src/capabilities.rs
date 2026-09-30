//! Opaque database capability contexts.
//!
//! The web tier selects the read feature and a database-enforced read-only
//! principal. Only the API or explicitly delegated workers select write.

use std::sync::Arc;

use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, DbErr, Statement};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatabaseFlavor {
    PostgreSql,
    CockroachDb,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorContext(String);

impl ActorContext {
    pub fn new(value: impl Into<String>) -> Result<Self, CapabilityError> {
        bounded_context(value.into(), "actor").map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantContext(String);

impl TenantContext {
    pub fn new(value: impl Into<String>) -> Result<Self, CapabilityError> {
        bounded_context(value.into(), "tenant").map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessScope {
    actor: ActorContext,
    tenant: TenantContext,
}

impl AccessScope {
    pub fn new(actor: ActorContext, tenant: TenantContext) -> Self {
        Self { actor, tenant }
    }

    pub fn actor(&self) -> &ActorContext {
        &self.actor
    }

    pub fn tenant(&self) -> &TenantContext {
        &self.tenant
    }
}

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("{0} context must contain 1..160 printable characters")]
    InvalidContext(&'static str),
    #[error("database operation failed")]
    Database(#[from] DbErr),
    #[error("database did not enforce a read-only transaction default")]
    ReadOnlyNotEnforced,
    #[error("database URL is not PostgreSQL-compatible")]
    UnsupportedDatabase,
}

#[derive(Clone)]
pub struct ReadContext {
    connection: Arc<DatabaseConnection>,
    scope: AccessScope,
    flavor: DatabaseFlavor,
}

impl ReadContext {
    pub async fn connect(database_url: &str, scope: AccessScope) -> Result<Self, CapabilityError> {
        let flavor = database_flavor(database_url)?;
        let connection = Database::connect(database_url).await?;
        connection
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                "set default_transaction_read_only = on".to_owned(),
            ))
            .await?;
        let result = connection
            .query_one(Statement::from_string(
                DatabaseBackend::Postgres,
                "show default_transaction_read_only".to_owned(),
            ))
            .await?
            .ok_or(CapabilityError::ReadOnlyNotEnforced)?;
        let setting: String = result.try_get("", "default_transaction_read_only")?;
        if !matches!(setting.as_str(), "on" | "true") {
            return Err(CapabilityError::ReadOnlyNotEnforced);
        }
        Ok(Self {
            connection: Arc::new(connection),
            scope,
            flavor,
        })
    }

    pub fn scope(&self) -> &AccessScope {
        &self.scope
    }

    pub fn flavor(&self) -> DatabaseFlavor {
        self.flavor
    }

    pub async fn health_check(&self) -> Result<(), CapabilityError> {
        self.connection
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                "select 1".to_owned(),
            ))
            .await?;
        Ok(())
    }
}

#[cfg(feature = "write")]
#[derive(Clone)]
pub struct WriteContext {
    connection: Arc<DatabaseConnection>,
    scope: AccessScope,
    flavor: DatabaseFlavor,
}

#[cfg(feature = "write")]
impl WriteContext {
    pub async fn connect(database_url: &str, scope: AccessScope) -> Result<Self, CapabilityError> {
        let flavor = database_flavor(database_url)?;
        let connection = Database::connect(database_url).await?;
        Ok(Self {
            connection: Arc::new(connection),
            scope,
            flavor,
        })
    }

    pub fn scope(&self) -> &AccessScope {
        &self.scope
    }

    pub fn flavor(&self) -> DatabaseFlavor {
        self.flavor
    }

    pub async fn health_check(&self) -> Result<(), CapabilityError> {
        self.connection
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                "select 1".to_owned(),
            ))
            .await?;
        Ok(())
    }
}

pub fn database_flavor(database_url: &str) -> Result<DatabaseFlavor, CapabilityError> {
    let normalized = database_url.to_ascii_lowercase();
    if !(normalized.starts_with("postgres://") || normalized.starts_with("postgresql://")) {
        return Err(CapabilityError::UnsupportedDatabase);
    }
    if normalized.contains("cockroach") {
        Ok(DatabaseFlavor::CockroachDb)
    } else {
        Ok(DatabaseFlavor::PostgreSql)
    }
}

fn bounded_context(value: String, label: &'static str) -> Result<String, CapabilityError> {
    let valid = !value.is_empty()
        && value.len() <= 160
        && value.chars().all(|character| !character.is_control());
    valid
        .then_some(value)
        .ok_or(CapabilityError::InvalidContext(label))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_fail_closed() {
        assert!(ActorContext::new("").is_err());
        assert!(TenantContext::new("tenant\nother").is_err());
    }

    #[test]
    fn classifies_both_supported_engines() {
        assert_eq!(
            database_flavor("postgresql://db/product").unwrap(),
            DatabaseFlavor::PostgreSql
        );
        assert_eq!(
            database_flavor("postgresql://cockroachdb/product").unwrap(),
            DatabaseFlavor::CockroachDb
        );
    }
}
