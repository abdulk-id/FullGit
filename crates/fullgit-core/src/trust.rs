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
pub type RetentionMap = BTreeMap<Oid, Oid>;

/// Whether `op` in `entity` is still valid under a revocation's retention map.
pub fn kept(repo: &Repository, retention: &RetentionMap, entity: Oid, op: Oid) -> bool {
    retention
        .get(&entity)
        .is_some_and(|&head| head == op || repo.graph_descendant_of(head, op).unwrap_or(false))
}

/// Serializes a retention map for a JSON `keep` field.
pub fn retention_to_json(retention: &RetentionMap) -> serde_json::Value {
    retention
        .iter()
        .map(|(e, h)| (e.to_string(), h.to_string().into()))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

/// Parses a payload's `keep` field; absent means nothing is kept.
pub fn retention_from_json(payload: &serde_json::Value) -> Result<RetentionMap, String> {
    let Some(v) = payload.get("keep") else {
        return Ok(RetentionMap::new());
    };
    let map: &serde_json::Map<String, serde_json::Value> =
        v.as_object().ok_or("keep is not an object")?;
    map.iter()
        .map(|(e, h)| {
            let h: &str = h.as_str().ok_or("keep values must be strings")?;
            Ok((crate::payload::parse_oid(e)?, crate::payload::parse_oid(h)?))
        })
        .collect()
}

/// The current heads of every local entity holding an operation signed by
/// one of `keys`: what a revocation of those keys should keep.
pub fn retention_for(repo: &Repository, keys: &[KeyData]) -> Result<RetentionMap> {
    let mut retention: RetentionMap = RetentionMap::new();
    for r in repo.references_glob(&format!("{}*", refs::PREFIX))? {
        let r: git2::Reference = r?;
        if r.name().is_ok_and(|n: &str| n.starts_with(refs::CODE_PREFIX)) {
            continue;
        }
        let Some(head): Option<Oid> = r.target() else {
            continue;
        };
        let Ok(ops) = entity::load(repo, &[head]) else {
            continue;
        };
        let signed: bool = ops
            .iter()
            .any(|o| o.op.kind != entity::MERGE_KIND && keys.contains(&o.signer));
        if signed && let Some(root) = ops.iter().find(|o| o.parents.is_empty()) {
            retention.insert(root.id, head);
        }
    }
    Ok(retention)
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
/// Without a policy (no `.fullgit/root` and no `fullgit.root`), nobody
/// holds a role: issues and pull requests need a policy.
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
        let mut trust: Trust = Self::load_identities(repo)?;
        if let Some(root) = policy::root(repo)? {
            let policy: model::Loaded<Policy> = model::load::<Policy>(repo, &trust, root).map_err(|e| match e {
                Error::NotFound(_) => Error::Policy(format!(
                    "policy {root} is not in this clone; run `fullgit sync`"
                )),
                e => e,
            })?;
            trust.policy = Some((root, policy.model));
        }
        Ok(trust)
    }

    /// Loads the identities only, without the policy.
    pub fn load_identities(repo: &Repository) -> Result<Self> {
        let mut trust: Trust = Self::default();
        let mut identities: BTreeMap<Oid, Identity> = BTreeMap::new();
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
        self.policy.as_ref().and_then(|(_, p)| p.role(identity))
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
    let mut best: Actor = Actor {
        identity: None,
        role: None,
    };
    for (id, identity) in identities {
        if !identity.signs(repo, &op.signer, entity, op.id) {
            continue;
        }
        let role: Option<Role> = policy.and_then(|p| p.role_for(repo, *id, entity, op.id));
        if best.identity.is_none() || role > best.role {
            best = Actor {
                identity: Some(*id),
                role,
            };
        }
    }
    best
}
