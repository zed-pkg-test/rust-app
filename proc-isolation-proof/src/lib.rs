//! Rootless, fail-closed process isolation for macOS and Linux.
//!
//! The crate intentionally splits policy resolution (Rust) from OS sandbox
//! mechanics (small reviewed shell helpers). Public CLI parsing is delegated to
//! `flags-2-env`; process/group resolution uses `ores-reactive-maps`.

pub mod config;
pub mod error;
pub mod flags;
pub mod platform;
pub mod runner;

pub use config::{Config, ResolvedProcess};
pub use error::{Error, Result};
