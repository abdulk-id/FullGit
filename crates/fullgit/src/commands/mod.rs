//! CLI subcommand modules: each file defines a `*Cmd` clap enum and a `run` entry point.

pub mod doctor;
pub mod hook;
pub mod id;
pub mod issue;
pub mod local;
pub mod policy;
pub mod pr;
pub mod secret;
