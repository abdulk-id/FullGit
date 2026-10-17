//! Identities: a name, an email and the SSH keys a person signs with. An
//! identity is only a claim; trust comes from the policy.
//!
//! Ops: `identity.create {name, email}` (the signing key becomes the first
//! key), `identity.edit {name?, email?}`, `identity.add_key {key, proof}`,
//! `identity.remove_key {key, keep}`. All but the first must be signed by a
//! key the identity holds.

use git2::{Oid, Repository};
use serde_json::json;
use ssh_key::public::KeyData;

use crate::model::{self, Ctx, Model};
use crate::op::StoredOp;
use crate::payload;
use crate::sign::{self, Signer, key_to_string};
use crate::trust::{Keep, Trust, keep_from_json, keep_to_json, kept};
use crate::{Error, Result};

/// Signature namespace for proofs of key possession, so a proof can't be
/// replayed as a commit signature or vice versa.
pub const PROOF_NAMESPACE: &str = "fullgit-key";

#[derive(Debug, Default, Clone)]
pub struct Identity {
    pub name: String,
    pub email: String,
    /// Current keys, in the order they were added.
    pub keys: Vec<KeyData>,
    /// Removed keys and what each removal kept.
    pub removed: Vec<(KeyData, Keep)>,
}

impl Identity {
    /// Whether `key` signs for this identity on operation `op` of `entity`:
    /// it is a current key, or a removed key whose removal kept `op`.
    pub fn signs(&self, repo: &Repository, key: &KeyData, entity: Oid, op: Oid) -> bool {
        self.keys.contains(key)
            || self
                .removed
                .iter()
                .any(|(k, keep)| k == key && kept(repo, keep, entity, op))
    }

    /// Every key that ever signed for this identity.
    pub fn all_keys(&self) -> Vec<KeyData> {
        let mut keys = self.keys.clone();
        for (k, _) in &self.removed {
            if !keys.contains(k) {
                keys.push(k.clone());
            }
        }
        keys
    }
}

impl Model for Identity {
    const NAMESPACE: &'static str = "identities";

    fn apply(&mut self, op: &StoredOp, ctx: &Ctx) -> Result<(), String> {
        let p = &op.op.payload;
        if op.parents.is_empty() {
            if op.op.kind != "identity.create" {
                return Err(format!("{} cannot create an identity", op.op.kind));
            }
            let (name, email) = (payload::str(p, "name")?, payload::str(p, "email")?);
            self.name = name.to_owned();
            self.email = email.to_owned();
            self.keys = vec![op.signer.clone()];
            return Ok(());
        }
        self.still_valid(op, ctx)?;
        match op.op.kind.as_str() {
            "identity.edit" => {
                let name = payload::opt_str(p, "name")?;
                let email = payload::opt_str(p, "email")?;
                if let Some(name) = name {
                    self.name = name.to_owned();
                }
                if let Some(email) = email {
                    self.email = email.to_owned();
                }
            }
            "identity.add_key" => {
                let key =
                    sign::key_from_string(payload::str(p, "key")?).map_err(|e| e.to_string())?;
                if self.keys.contains(&key) {
                    return Err("key is already present".into());
                }
                let proof = payload::str(p, "proof")?;
                let prover = sign::verify_as(
                    PROOF_NAMESPACE,
                    proof_message(ctx.entity, &key).as_bytes(),
                    proof,
                )
                .map_err(|e| format!("bad proof: {e}"))?;
                if prover != key {
                    return Err("proof is not signed by the added key".into());
                }
                self.keys.push(key);
            }
            "identity.remove_key" => {
                let key =
                    sign::key_from_string(payload::str(p, "key")?).map_err(|e| e.to_string())?;
                let keep = keep_from_json(p)?;
                let Some(i) = self.keys.iter().position(|k| *k == key) else {
                    return Err("key is not present".into());
                };
                if self.keys.len() == 1 {
                    return Err("cannot remove the last key".into());
                }
                self.keys.remove(i);
                self.removed.push((key, keep));
            }
            kind => return Err(format!("unknown operation {kind}")),
        }
        Ok(())
    }

    fn still_valid(&self, op: &StoredOp, ctx: &Ctx) -> Result<(), String> {
        if self.signs(ctx.repo, &op.signer, ctx.entity, op.id) {
            Ok(())
        } else {
            Err("not signed by a key of this identity".into())
        }
    }
}

/// What a new key signs to prove it belongs to the identity's owner.
/// Without this, anyone could add someone else's public key to their
/// identity and be credited with that person's operations.
pub fn proof_message(identity: Oid, key: &KeyData) -> String {
    format!(
        "fullgit add-key\nidentity {identity}\nkey {}\n",
        key_to_string(key)
    )
}

/// Signs a proof with `new_key` that it may be added to `identity`.
pub fn prove(new_key: &dyn Signer, identity: Oid) -> Result<String> {
    let message = proof_message(identity, new_key.public_key().key_data());
    new_key.sign_as(PROOF_NAMESPACE, message.as_bytes())
}

pub fn create(repo: &Repository, signer: &dyn Signer, name: &str, email: &str) -> Result<Oid> {
    model::create::<Identity>(
        repo,
        &Trust::default(),
        signer,
        "identity.create",
        json!({ "name": name, "email": email }),
    )
}

pub fn edit(
    repo: &Repository,
    id: Oid,
    signer: &dyn Signer,
    name: Option<&str>,
    email: Option<&str>,
) -> Result<Oid> {
    update(
        repo,
        id,
        signer,
        "identity.edit",
        json!({ "name": name, "email": email }),
    )
}

pub fn add_key(
    repo: &Repository,
    id: Oid,
    signer: &dyn Signer,
    key: &KeyData,
    proof: &str,
) -> Result<Oid> {
    update(
        repo,
        id,
        signer,
        "identity.add_key",
        json!({ "key": key_to_string(key), "proof": proof }),
    )
}

/// Removes `key`. Operations it signed so far, in this clone, stay
/// attributed to the identity; anything else it signs no longer is.
pub fn remove_key(repo: &Repository, id: Oid, signer: &dyn Signer, key: &KeyData) -> Result<Oid> {
    let keep = crate::trust::keep_for(repo, std::slice::from_ref(key))?;
    update(
        repo,
        id,
        signer,
        "identity.remove_key",
        json!({ "key": key_to_string(key), "keep": keep_to_json(&keep) }),
    )
}

pub fn load(repo: &Repository, id: Oid) -> Result<Identity> {
    Ok(model::load::<Identity>(repo, &Trust::default(), id)?.model)
}

fn update(
    repo: &Repository,
    id: Oid,
    signer: &dyn Signer,
    kind: &str,
    payload: serde_json::Value,
) -> Result<Oid> {
    model::update::<Identity>(repo, &Trust::default(), id, signer, kind, payload).map_err(|e| {
        match e {
            Error::NotFound(_) => Error::NotFound(format!("identity {id}")),
            e => e,
        }
    })
}
