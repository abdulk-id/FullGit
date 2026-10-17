//! The policy: which identity holds which role, and named groups. Lives at
//! `refs/fullgit/policy/<genesis-id>`. Only owners may change it.
//!
//! Which policy a clone trusts is pinned: `.fullgit/root` in the committed
//! tree names the genesis, and `fullgit.root` in the clone's git config
//! records the one it accepted. A different genesis, e.g. pushed by someone
//! who wants to be owner, is refused rather than silently trusted.
//!
//! Ops: `policy.genesis {owners}`, `policy.grant {identity, role, keep?}`,
//! `policy.revoke {identity, keep}`, `policy.group_add {group, identity}`,
//! `policy.group_remove {group, identity}`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use git2::{Oid, Repository};
use serde_json::json;

use crate::model::{self, Ctx, Model};
use crate::op::StoredOp;
use crate::payload;
use crate::sign::Signer;
use crate::trust::{self, Keep, Role, Trust, keep_from_json, keep_to_json, kept};
use crate::{Error, Result};

pub const ROOT_FILE: &str = ".fullgit/root";
pub const ROOT_CONFIG: &str = "fullgit.root";

#[derive(Debug, Default, Clone)]
pub struct Policy {
    roles: BTreeMap<Oid, Role>,
    /// Roles taken away (by a revoke or a lower grant), each with what its
    /// removal kept.
    demotions: BTreeMap<Oid, Vec<(Role, Keep)>>,
    pub groups: BTreeMap<String, BTreeSet<Oid>>,
}

impl Policy {
    /// The role `identity` holds now.
    pub fn role(&self, identity: Oid) -> Option<Role> {
        self.roles.get(&identity).copied()
    }

    pub fn roles(&self) -> &BTreeMap<Oid, Role> {
        &self.roles
    }

    /// The role `identity` held for operation `op` of `entity`: its current
    /// role, or a higher one it lost later if that loss kept `op`.
    pub fn role_for(&self, repo: &Repository, identity: Oid, entity: Oid, op: Oid) -> Option<Role> {
        let before = self
            .demotions
            .get(&identity)
            .into_iter()
            .flatten()
            .filter(|(_, keep)| kept(repo, keep, entity, op))
            .map(|(role, _)| *role)
            .max();
        self.role(identity).max(before)
    }

    fn set_role(&mut self, identity: Oid, role: Option<Role>, keep: Keep) -> Result<(), String> {
        let old = self.role(identity);
        if old == role {
            return Err(match role {
                Some(r) => format!("{identity} is already {r}"),
                None => format!("{identity} holds no role"),
            });
        }
        let owners = self.roles.values().filter(|r| **r == Role::Owner).count();
        if old == Some(Role::Owner) && owners == 1 {
            return Err("the policy must keep at least one owner".into());
        }
        if let Some(old) = old
            && Some(old) > role
        {
            self.demotions
                .entry(identity)
                .or_default()
                .push((old, keep));
        }
        match role {
            Some(r) => self.roles.insert(identity, r),
            None => self.roles.remove(&identity),
        };
        Ok(())
    }
}

impl Model for Policy {
    const NAMESPACE: &'static str = "policy";

    fn apply(&mut self, op: &StoredOp, ctx: &Ctx) -> Result<(), String> {
        let p = &op.op.payload;
        if op.parents.is_empty() {
            if op.op.kind != "policy.genesis" {
                return Err(format!("{} cannot create a policy", op.op.kind));
            }
            let owners = p["owners"]
                .as_array()
                .ok_or("missing owners")?
                .iter()
                .map(|v| payload::parse_oid(v.as_str().ok_or("owners must be ids")?))
                .collect::<Result<BTreeSet<_>, _>>()?;
            let signed_by_owner = owners.iter().any(|id| {
                ctx.trust
                    .identities
                    .get(id)
                    .is_some_and(|i| i.signs(ctx.repo, &op.signer, ctx.entity, op.id))
            });
            if !signed_by_owner {
                return Err("genesis must be signed by one of its owners".into());
            }
            self.roles = owners.into_iter().map(|id| (id, Role::Owner)).collect();
            return Ok(());
        }

        self.still_valid(op, ctx)?;
        match op.op.kind.as_str() {
            "policy.grant" => {
                let identity = payload::oid(p, "identity")?;
                let role = payload::str(p, "role")?.parse()?;
                self.set_role(identity, Some(role), keep_from_json(p)?)
            }
            "policy.revoke" => {
                let identity = payload::oid(p, "identity")?;
                self.set_role(identity, None, keep_from_json(p)?)
            }
            "policy.group_add" => {
                let (group, identity) = group_member(p)?;
                if !self
                    .groups
                    .entry(group.clone())
                    .or_default()
                    .insert(identity)
                {
                    return Err(format!("{identity} is already in {group}"));
                }
                Ok(())
            }
            "policy.group_remove" => {
                let (group, identity) = group_member(p)?;
                let members = self.groups.get_mut(&group);
                if !members.is_some_and(|m| m.remove(&identity)) {
                    return Err(format!("{identity} is not in {group}"));
                }
                self.groups.retain(|_, m| !m.is_empty());
                Ok(())
            }
            kind => Err(format!("unknown operation {kind}")),
        }
    }

    /// Owners act on the policy. Re-checked against the final state, so an
    /// owner's operations that their revocation didn't keep are dropped.
    fn still_valid(&self, op: &StoredOp, ctx: &Ctx) -> Result<(), String> {
        trust::actor(ctx.repo, &ctx.trust.identities, Some(self), ctx.entity, op)
            .require(Role::Owner)
    }
}

fn group_member(p: &serde_json::Value) -> Result<(String, Oid), String> {
    let group = payload::str(p, "group")?;
    if group.is_empty() {
        return Err("group name is empty".into());
    }
    Ok((group.to_owned(), payload::oid(p, "identity")?))
}

/// The policy this clone trusts: the pinned one, else the committed one.
/// Fails if the committed root differs from the pinned one.
pub fn root(repo: &Repository) -> Result<Option<Oid>> {
    let pinned = pinned_root(repo)?;
    let committed = committed_root(repo)?;
    match (pinned, committed) {
        (Some(p), Some(c)) if p != c => Err(Error::Policy(format!(
            "{ROOT_FILE} names policy {c}, but this clone trusts {p} ({ROOT_CONFIG}); \
             if the change is intended, run `git config {ROOT_CONFIG} {c}`"
        ))),
        (Some(p), _) => Ok(Some(p)),
        (None, c) => Ok(c),
    }
}

pub fn pinned_root(repo: &Repository) -> Result<Option<Oid>> {
    match repo.config()?.get_string(ROOT_CONFIG) {
        Ok(s) => Ok(Some(parse_root(&s, ROOT_CONFIG)?)),
        Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// `.fullgit/root` in `HEAD`'s tree.
pub fn committed_root(repo: &Repository) -> Result<Option<Oid>> {
    let head = match repo.head() {
        Ok(h) => h,
        Err(e)
            if matches!(
                e.code(),
                git2::ErrorCode::UnbornBranch | git2::ErrorCode::NotFound
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    };
    let tree = head.peel_to_tree()?;
    let entry = match tree.get_path(Path::new(ROOT_FILE)) {
        Ok(e) => e,
        Err(e) if e.code() == git2::ErrorCode::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let blob = repo.find_blob(entry.id())?;
    let s = String::from_utf8_lossy(blob.content());
    Ok(Some(parse_root(&s, ROOT_FILE)?))
}

fn parse_root(s: &str, from: &str) -> Result<Oid> {
    payload::parse_oid(s.trim()).map_err(|e| Error::Policy(format!("{from}: {e}")))
}

/// Records `root` as the policy this clone trusts.
pub fn pin(repo: &Repository, root: Oid) -> Result<()> {
    repo.config()?.set_str(ROOT_CONFIG, &root.to_string())?;
    Ok(())
}

/// Writes `.fullgit/root` into the working tree, for the user to commit.
pub fn write_root_file(repo: &Repository, root: Oid) -> Result<std::path::PathBuf> {
    let workdir = repo
        .workdir()
        .ok_or_else(|| Error::Policy("a bare repository has no working tree".into()))?;
    let path = workdir.join(ROOT_FILE);
    std::fs::create_dir_all(path.parent().expect("ROOT_FILE has a parent"))?;
    std::fs::write(&path, format!("{root}\n"))?;
    Ok(path)
}

/// Creates a policy owned by `owners` and pins it. `signer` must hold a key
/// of one of them.
pub fn genesis(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    owners: &[Oid],
) -> Result<Oid> {
    let owners: Vec<_> = owners.iter().map(Oid::to_string).collect();
    let root = model::create::<Policy>(
        repo,
        trust,
        signer,
        "policy.genesis",
        json!({ "owners": owners }),
    )?;
    pin(repo, root)?;
    Ok(root)
}

/// Gives `identity` a role. Lowering a role keeps the identity's
/// operations already in this clone at the old role.
pub fn grant(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    identity: Oid,
    role: Role,
) -> Result<Oid> {
    let (_, policy) = loaded(trust)?;
    let mut payload = json!({ "identity": identity.to_string(), "role": role });
    if policy.role(identity) > Some(role) {
        payload["keep"] = keep_to_json(&keep_of(repo, trust, identity)?);
    }
    update(repo, trust, signer, "policy.grant", payload)
}

/// Takes away `identity`'s role. Its operations already in this clone stay
/// valid; anything it signs later, or backdates, does not.
pub fn revoke(repo: &Repository, trust: &Trust, signer: &dyn Signer, identity: Oid) -> Result<Oid> {
    let keep = keep_of(repo, trust, identity)?;
    update(
        repo,
        trust,
        signer,
        "policy.revoke",
        json!({ "identity": identity.to_string(), "keep": keep_to_json(&keep) }),
    )
}

pub fn group_add(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    group: &str,
    identity: Oid,
) -> Result<Oid> {
    update(
        repo,
        trust,
        signer,
        "policy.group_add",
        json!({ "group": group, "identity": identity.to_string() }),
    )
}

pub fn group_remove(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    group: &str,
    identity: Oid,
) -> Result<Oid> {
    update(
        repo,
        trust,
        signer,
        "policy.group_remove",
        json!({ "group": group, "identity": identity.to_string() }),
    )
}

fn loaded(trust: &Trust) -> Result<&(Oid, Policy)> {
    trust
        .policy
        .as_ref()
        .ok_or_else(|| Error::Policy("no policy; run `fullgit policy init`".into()))
}

fn keep_of(repo: &Repository, trust: &Trust, identity: Oid) -> Result<Keep> {
    let keys = trust
        .identities
        .get(&identity)
        .map(|i| i.all_keys())
        .unwrap_or_default();
    trust::keep_for(repo, &keys)
}

fn update(
    repo: &Repository,
    trust: &Trust,
    signer: &dyn Signer,
    kind: &str,
    payload: serde_json::Value,
) -> Result<Oid> {
    let (root, _) = loaded(trust)?;
    model::update::<Policy>(repo, trust, *root, signer, kind, payload)
}
