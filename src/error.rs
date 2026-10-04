use thiserror::Error;

#[derive(Debug, Error)]
pub enum OrmError {
    #[error("could not parse Rust source: {0}")]
    RustParse(#[from] syn::Error),
    #[error("could not parse ORM policy: {0}")]
    PolicyParse(#[from] toml::de::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported ORM construct: {0}")]
    Unsupported(String),
    #[error("invalid ORM input: {0}")]
    Invalid(String),
    #[error("ORM parity failed: {0}")]
    Parity(String),
}

pub type Result<T> = std::result::Result<T, OrmError>;
