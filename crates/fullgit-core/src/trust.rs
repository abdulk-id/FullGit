//! Who signed an operation, and what they were allowed to do. Combines the
//! identities (key → person) with the policy (person → role).

use std::collections::BTreeMap;

use git2::{Oid, Repository};
use serde::{Deserialize, Serialize};
use ssh_key::public::KeyData;

use crate::identity::Identity;
use crate::model;
use crate::policy::{self, Policy};
use crate::refs;
use crate::{Error, Result, entity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Reader,
    Contributor,
    Maintainer,
    Owner,
}

impl Role {
    pub const ALL: [Role; 4] = [
        Role::Reader,
        Role::Contributor,
        Role::Maintainer,
        Role::Owner,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Reader => "reader",
            Role::Contributor => "contributor",
            Role::Maintainer => "maintainer",
            Role::Owner => "owner",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

impl std::str::FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Role::ALL
            .into_iter()
            .find(|r| r.as_str() == s)
            .ok_or_else(|| format!("unknown role {s}"))
    }
}

/// What a revocation keeps: entity id → that entity's head when the
/// revocation was written. An operation by the revoked key or identity stays
/// valid only if it is an ancestor of the kept head of its entity, i.e. the
/// revoker had seen it. Operations written later, or backdated onto old
/// parents, are not kept.
pub type Keep = BTreeMap<Oid, Oid>;

pub fn kept(repo: &Repository, keep: &Keep, entity: Oid, op: Oid) -> bool {
    keep.get(&entity)
        .is_some_and(|&head| head == op || repo.graph_descendant_of(head, op).unwrap_or(false))
}

pub fn keep_to_json(keep: &Keep) -> serde_json::Value {
    keep.iter()
        .map(|(e, h)| (e.to_string(), h.to_string().into()))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

/// Parses a payload's `keep` field; absent means nothing is kept.
pub fn keep_from_json(payload: &serde_json::Value) -> Result<Keep, String> {
    let Some(v) = payload.get("keep") else {
        return Ok(Keep::new());
    };
    let map = v.as_object().ok_or("keep is not an object")?;
    map.iter()
        .map(|(e, h)| {
            let h = h.as_str().ok_or("keep values must be strings")?;
            Ok((crate::payload::parse_oid(e)?, crate::payload::parse_oid(h)?))
        })
        .collect()
}

/// The current heads of every local entity holding an operation signed by
/// one of `keys`: what a revocation of those keys should keep.
pub fn keep_for(repo: &Repository, keys: &[KeyData]) -> Result<Keep> {
    let mut keep = Keep::new();
    for r in repo.references_glob(&format!("{}*", refs::PREFIX))? {
        let Some(head) = r?.target() else { continue };
        let Ok(ops) = entity::load(repo, &[head]) else {
            continue;
        };
        let signed = ops
            .iter()
            .any(|o| o.op.kind != entity::MERGE_KIND && keys.contains(&o.signer));
        if signed && let Some(root) = ops.iter().find(|o| o.parents.is_empty()) {
            keep.insert(root.id, head);
        }
    }
    Ok(keep)
}

/// The signer of an operation and the role they held for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// `None` if no identity claims the signing key.
    pub identity: Option<Oid>,
    /// `None` if the identity holds no role.
    pub role: Option<Role>,
}

impl Actor {
    pub fn require(&self, role: Role) -> Result<(), String> {
        if self.role >= Some(role) {
            return Ok(());
        }
        Err(match (self.identity, self.role) {
            (None, _) => "signed by a key that belongs to no identity".into(),
            (Some(id), None) => format!("identity {id} holds no role; {role} required"),
            (Some(id), Some(has)) => format!("identity {id} is {has}; {role} required"),
        })
    }
}

/// Identities and the policy, loaded once and consulted for every operation.
///
/// Without a policy (no `.fullgit/root` and no `fullgit.root`), nothing is
/// restricted: every signer acts as an owner.
#[derive(Default)]
pub struct Trust {
    pub identities: BTreeMap<Oid, Identity>,
    /// Identities whose log failed to load, and why.
    pub invalid: Vec<(Oid, String)>,
    pub policy: Option<(Oid, Policy)>,
}

impl Trust {
    /// Loads every local identity, then the trusted policy if there is one.
    pub fn load(repo: &Repository) -> Result<Self> {
        let mut trust = Self::load_identities(repo)?;
        if let Some(root) = policy::root(repo)? {
            let policy = model::load::<Policy>(repo, &trust, root).map_err(|e| match e {
                Error::NotFound(_) => Error::Policy(format!(
                    "policy {root} is not in this clone; run `fullgit sync`"
                )),
                e => e,
            })?;
            trust.policy = Some((root, policy.model));
        }
        Ok(trust)
    }

    /// Loads the identities only; nothing is restricted.
    pub fn load_identities(repo: &Repository) -> Result<Self> {
        let mut trust = Self::default();
        let mut identities = BTreeMap::new();
        for id in model::list::<Identity>(repo)? {
            match model::load::<Identity>(repo, &trust, id) {
                Ok(loaded) => {
                    identities.insert(id, loaded.model);
                }
                Err(e) => trust.invalid.push((id, e.to_string())),
            }
        }
        trust.identities = identities;
        Ok(trust)
    }

    pub fn restricted(&self) -> bool {
        self.policy.is_some()
    }

    /// Identities currently holding `key`.
    pub fn identities_with_key(&self, key: &KeyData) -> Vec<Oid> {
        self.identities
            .iter()
            .filter(|(_, i)| i.keys.contains(key))
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn role(&self, identity: Oid) -> Option<Role> {
        match &self.policy {
            Some((_, p)) => p.role(identity),
            None => Some(Role::Owner),
        }
    }

    pub fn actor(&self, repo: &Repository, entity: Oid, op: &crate::StoredOp) -> Actor {
        actor(
            repo,
            &self.identities,
            self.policy.as_ref().map(|(_, p)| p),
            entity,
            op,
        )
    }
}

/// Resolves the signer of `op` (in `entity`) under `policy`. If several
/// identities hold the key, the one with the highest role wins, then the
/// lowest id; all of them proved possession of the key, so this only
/// matters for display.
pub fn actor(
    repo: &Repository,
    identities: &BTreeMap<Oid, Identity>,
    policy: Option<&Policy>,
    entity: Oid,
    op: &crate::StoredOp,
) -> Actor {
    let mut best = Actor {
        identity: None,
        role: None,
    };
    for (id, identity) in identities {
        if !identity.signs(repo, &op.signer, entity, op.id) {
            continue;
        }
        let role = match policy {
            Some(p) => p.role_for(repo, *id, entity, op.id),
            None => Some(Role::Owner),
        };
        if best.identity.is_none() || role > best.role {
            best = Actor {
                identity: Some(*id),
                role,
            };
        }
    }
    if policy.is_none() {
        best.role = Some(Role::Owner);
    }
    best
}
