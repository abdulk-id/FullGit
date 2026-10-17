//! Core library for fullgit: signed operation logs stored as git commits under
//! `refs/fullgit/*`. See `DESIGN.md` at the repository root.

pub mod entity;
pub mod filter;
pub mod identity;
pub mod model;
pub mod op;
pub mod payload;
pub mod policy;
pub mod refs;
pub mod remote;
pub mod secret;
pub mod setup;
pub mod sign;
pub mod sync;
pub mod trust;

pub use entity::{Merged, append, load, merge};
pub use identity::Identity;
pub use model::{Ctx, Model};
pub use op::{Op, StoredOp, read_op, write_op};
pub use policy::Policy;
pub use sign::{Signer, SshKeygenSigner, verify};
pub use trust::{Actor, Role, Trust};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Git(#[from] git2::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("signature: {0}")]
    Signature(String),
    #[error("malformed operation {oid}: {reason}")]
    Malformed { oid: git2::Oid, reason: String },
    #[error("ref {0} changed concurrently; retry")]
    Conflict(String),
    #[error("{0} has diverged and merging it needs a signing key")]
    NeedsSigner(String),
    #[error("operation {op} rejected: {reason}")]
    Rejected { op: git2::Oid, reason: String },
    #[error("no entity matches {0}")]
    NotFound(String),
    #[error("{0} matches more than one entity")]
    Ambiguous(String),
    #[error("policy: {0}")]
    Policy(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
