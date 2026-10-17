# FullGit — design

Status: **draft, Phase 3**.

## Goals

Make these travel with the repository, using any git host (GitHub, GitLab, a bare
server) as plain storage:

1. **Permissions** — who may do what.
2. **Issues**.
3. **Pull requests**, with line-level review.
4. **Secret files** (e.g. `.env`) committed encrypted.
5. **Per-user files** (e.g. `mise.local.toml`) committed encrypted to their owner.

Non-goals for now: wiki, CI, boards, a hosted server, replacing the host's own
push access control.

## Threat model: what "permissions" can mean on a dumb host

A git host stores refs and enforces exactly one thing: who may push. Anyone with
push access can write any ref. So:

- **Write permissions** are enforced by every client: each operation is signed,
  and clients ignore operations whose signer was not authorized by the policy.
- **Read permissions** can only be enforced by encryption.

A malicious pusher can delete or rewind refs (mitigated: every clone has a full
copy, and sync never accepts a non-fast-forward rewrite of an entity) and can
push garbage operations (ignored). They cannot forge someone else's operations
or read secrets that were not encrypted to them.

For self-hosted remotes, an optional `pre-receive` hook can reject invalid
operations before they land.

## Storage model

### Refs

```
refs/fullgit/identities/<id>
refs/fullgit/policy/<id>
refs/fullgit/issues/<id>
refs/fullgit/prs/<id>
refs/fullgit/users/<identity-id>/local
```

An entity's `<id>` is the hex oid of its root operation commit.

### Operations

Every change to an entity is one git commit:

- **tree**: a single `op.json` blob (attachments may add blobs later)
- **parents**: the entity's previous head(s)
- **signature**: git's native SSH commit signature (`gpgsig` header, namespace
  `git`). `git verify-commit` works on operations given an allowed-signers file.

```json
{ "v": 1, "type": "issue.comment", "lamport": 7, "payload": { "body": "..." } }
```

Commit timestamps are informational only and never used for ordering.

### Ordering and replay

- `lamport = 1 + max(lamport of parents)` (root is `1`).
- Replay order is a topological order of the operation DAG, ties broken by
  `(lamport, commit oid)`. Every machine computes the same order.
- Each entity type implements the `Model` trait: `apply(&mut state, op)`.
  Concurrent writes resolve through that order: last-writer-wins for scalar
  fields, set semantics for labels and assignees, append for comments.
- An op the model rejects (unknown type, bad payload, missing permission) is
  skipped and listed as rejected. Every replica skips the same ops. A
  rejected root makes the whole entity invalid.
- Models whose own state grants authority (identities, the policy) also
  re-check every applied op against the final state, because a later
  revocation can take back an op that was valid when applied. If one fails,
  the last failing op is dropped and the entity replayed without it (it may
  be the revocation that invalidated the others); repeat until stable.
- `model::update` applies an op to the current state before moving the ref,
  so a client never writes an op it would itself reject.
- Root ops get a `nonce` in their payload; otherwise two identical creations
  in the same second would be the same commit, and so the same entity.

### Sync

- `fullgit init` adds the fetch refspec
  `+refs/fullgit/*:refs/remotes/<remote>/fullgit/*`. It deliberately does **not**
  add a push refspec: setting `remote.<name>.push` changes what a bare
  `git push` pushes.
- `fullgit sync [<remote>]`: fetch, then for each entity:
  - verify the remote's version first: every op validly signed, consistent
    clocks, a single root, and for `<namespace>/<id>` refs, root = `<id>`;
  - remote head descends from local → fast-forward;
  - local descends from remote → nothing to do;
  - diverged → write a signed `merge` operation with both heads as parents
    (sorted). This is the only step that needs a signing key; without one,
    the entity is skipped until there is one.

  Then push every local `refs/fullgit/*` ref without forcing. If another
  writer won the race, fetch, merge and push again (up to 3 rounds).
- Refs whose remote version fails verification are **neither merged nor
  pushed**, and are reported. Sync doesn't overwrite them: a client on an
  older version would see ops in a newer format as invalid and destroy them.
  Repairing a bad remote ref is a deliberate human action.
- Deleting an entity ref on the remote doesn't delete it anywhere else: the
  next sync from any clone pushes it back.
- Network operations shell out to the system `git`, so the user's SSH and
  credential setup works unchanged.

## Identity

- Keys are **SSH ed25519**, the same keys developers already use for git
  signing. The signing key comes from `user.signingkey`.
- Signing shells out to `ssh-keygen -Y sign`, exactly like git does, so
  ssh-agent and passphrase-protected keys work. Verification is in-process.
- Identity ops:
  - `identity.create {name, email}`: the signing key becomes the first key.
  - `identity.edit {name?, email?}`
  - `identity.add_key {key, proof}`: `proof` is the *new* key's signature
    (namespace `fullgit-key`) over the identity id and the key. Without it,
    anyone could add someone else's public key to their own identity and be
    credited with that person's operations.
  - `identity.remove_key {key, keep}`: see revocation below. The last key
    can't be removed.

  All but `create` must be signed by a key the identity holds.
- An identity is only a claim. Trust comes from the policy.
- CLI: `fullgit id create | show | list | edit | add-key | prove |
  remove-key`. Adding a key that lives on another machine: run
  `fullgit id prove <id>` there and pass its output to
  `fullgit id add-key --proof`.

## Permissions (policy)

- A `refs/fullgit/policy/<id>` entity. Its root op, `policy.genesis
  {owners}`, must be signed by one of the owners.
- **Which policy to trust** is pinned. The genesis id is committed to the
  main tree as `.fullgit/root`; `fullgit init` records it in the clone's
  config as `fullgit.root` (trust on first use). Afterwards a different
  committed root is refused until the user changes `fullgit.root`
  themselves, so pushing a new policy with yourself as owner doesn't work.
- Without a policy, nothing is restricted: every signer acts as an owner.
- Roles: `owner` > `maintainer` > `contributor` > `reader`. Groups are named
  sets of identities, e.g. `secrets:prod`.
- Ops: `policy.grant {identity, role, keep?}`, `policy.revoke {identity,
  keep}`, `policy.group_add {group, identity}`, `policy.group_remove`. Only
  owners change the policy, and the last owner can't be removed.
- An operation's **actor** is the identity holding its signing key, with that
  identity's role. Each entity type decides what role each op needs.
- **Revocation.** There's no trusted clock, so a revoked key could otherwise
  keep writing ops and claim they are old. A revocation (`policy.revoke`, a
  lowering `policy.grant`, or `identity.remove_key`) therefore records
  `keep`: for every entity holding ops by the revoked identity or key, the
  head the revoker had at that moment. Afterwards, an op by them counts
  (with their old role) only if it is an ancestor of the kept head of its
  entity. Ops the revoker hadn't seen, written later, or backdated onto
  old parents don't. Deterministic, and computed by the client that
  revokes.
- **Protected branches** (Phase 6): `policy.rule {protect: "main",
  approvals: 1}`. `fullgit verify main` checks that every first-parent commit
  on `main` is a merge recorded by a valid `pr.merge` op. Pushes can't be
  prevented on a dumb host, only detected; use the host's branch protection
  alongside where it exists.
- CLI: `fullgit policy init | show | grant | revoke | group add | group
  remove`.

## Secrets

- Declared in `.gitattributes`, so git does the pattern matching:

  ```
  .env       filter=fullgit diff=fullgit fullgit-group=dev
  .env.prod  filter=fullgit diff=fullgit fullgit-group=secrets:prod
  ```

  `fullgit secret add <path> --group <g>` writes these lines.
- Encrypted with **age** to every SSH key of every member of the group.
  Plaintext in the working tree, ciphertext in the repository.
- Implemented as a git filter driver using the long-running
  `filter.<driver>.process` protocol.
- age output is non-deterministic, so the clean filter reuses the blob already
  in the index when the plaintext is unchanged. Otherwise every `git status`
  would report changes.
- A `diff=fullgit` textconv driver gives plaintext diffs locally.
- Without the keys, checkout leaves the ciphertext in place instead of failing.
- Guards: a `pre-commit` hook refuses any staged secret whose blob is not valid
  fullgit ciphertext (this catches a misconfigured filter). `fullgit doctor`
  checks the setup.
- `fullgit secret rekey` re-encrypts to the current recipients after a
  membership change. It lists every secret the removed member could read,
  because git history still holds the old versions and those must be
  **rotated**.

## Per-user files

- Declared in `.gitattributes` with `fullgit-local`, and also listed in
  `.gitignore` (`fullgit local add` writes both):

  ```
  mise.local.toml  fullgit-local
  ```

- **One snapshot per user**, not per branch. `fullgit local save` collects the
  matching files from the working tree into one archive, encrypts it to the
  user's own keys only (all their devices), and commits it signed to
  `refs/fullgit/users/<my-id>/local`. Encrypting a single archive also hides
  the file names. Earlier snapshots stay in the ref's history for rollback.
- `fullgit local restore` decrypts the latest snapshot into the working tree.
  It refuses to overwrite locally modified files without `--force`.
- Hooks: `post-checkout` restores missing files after a fresh clone;
  `pre-push` saves when the files have changed.

## Issues

- State: title, body, status (open/closed), labels, assignees, comments.
- Ops: `issue.create`, `issue.edit`, `issue.comment`, `issue.comment_edit`,
  `issue.label`, `issue.assign`, `issue.status`.
- Permissions: contributors create and comment; the author or a maintainer
  edits and closes.

## Pull requests

- State: title, body, source and target branch, revisions `[{head, base, note}]`,
  review comments, reviews, status (open/merged/closed).
- Ops: `pr.create`, `pr.revise`, `pr.comment {revision, path, line, side}`,
  `pr.review {verdict}`, `pr.merge {merge_commit}`, `pr.close`.
- Source branches are ordinary branches on the remote.
- `fullgit pr merge` checks the policy (required approvals on the latest
  revision), merges locally with git, records `pr.merge`, and pushes the branch
  and the refs.

## Implementation

- Rust workspace:
  - `crates/fullgit-core`: library (operations, entities, policy, crypto).
  - `crates/fullgit`: the CLI. Installed as `fullgit` and as `git-fullgit`, so
    `git fullgit ...` also works.
- **git2** (libgit2, vendored) for objects and refs. Its `commit_signed` and
  `extract_signature` map exactly onto the operation format. gix was considered;
  its write-side API is still moving, so revisit later.
- **ssh-key** for in-process signature verification; `ssh-keygen` subprocess
  for signing.
- **age** for encryption. **clap** for the CLI.

## Phases

| Phase | Deliverable | Status |
|---|---|---|
| 0. Spike | Signed operation commits under `refs/fullgit/*`; verified by `git verify-commit`; survive push/fetch to a local bare repo; script to check real hosts | done; GitHub passes (2026-10-17), GitLab untested |
| 1. Engine | Entity library, deterministic replay, `sync` | done (2026-10-17) |
| 2. Identity + policy | `init`, `id`, roles, validation, revocation | done (2026-10-17) |
| 3. Secrets | Filter driver, age, guards, `rekey` | |
| 4. Per-user files | `local add/save/restore`, hooks | |
| 5. Issues | CLI: create, list, show, comment, close | |
| 6. PRs + review | Revisions, line comments, approvals, merge | |
| 7. UX + reach | TUI or local web UI, GitHub/GitLab bridge, server hook | |

## Open questions

- Revocation drops a revoked member's ops that the revoker hadn't fetched
  yet, even honest ones. There's no op to re-admit them yet.
- Owners are trusted equals. If two owners revoke each other concurrently,
  replay order decides, and a malicious owner can choose a clock that wins.
  Recovery is a new genesis and an explicit change of `fullgit.root`.
- A key held by a compromised machine can still be used to race the
  identity's other keys; the fix is an owner revoking the identity, and the
  person creating a new one.
- Contributors without push access (forks): how their operations reach the repo.
- Hosts: GitHub accepts, lists and serves `refs/fullgit/*` (checked
  2026-10-17; a test ref left in a private throwaway repo was still there 5
  hours later; check again for garbage collection over a longer period). GitLab and Bitbucket are untested.
  `scripts/check-remote.sh` runs the check.
- Scaling: thousands of entity refs make fetches slower. Entities may need
  packing into fewer refs later.
