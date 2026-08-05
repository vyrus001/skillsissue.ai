//! Safe, deterministic acquisition of agent skill trees.
//!
//! This crate deliberately keeps acquisition separate from detonation. It only
//! copies data, validates paths and limits, computes canonical identities using
//! `skills-core`, and updates repository-owned indexes.

mod catalog;
mod clawhub;
pub mod cli;
mod git;
mod platform;
mod prepare;
mod state;
mod worker;

pub use cli::{Cli, Command};
pub use platform::{AdapterKind, PlatformSource, load_enabled_platforms};
pub use prepare::{PreparedSkill, SecurityLimits, discover_skill_directories, prepare_skill};
pub use worker::{IngestRequest, IngestSummary, Worker};
