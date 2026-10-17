# FullGit — design

Status: **draft, Phase 6**.

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
  /.env       filter=fullgit diff=fullgit -merge -text fullgit-group=dev
  /.env.prod  filter=fullgit diff=fullgit -merge -text fullgit-group=secrets:prod
  ```

  `fullgit secret add <path> --group <g>` writes these lines. `-merge`
  makes git treat a conflict as binary rather than writing conflict
  markers into ciphertext; `-text` keeps line-ending conversion away from
  it.
- **Sealed format**: a short header, the age ciphertext (armored), and an SSH
  signature over both by whoever sealed it:

  ```
  fullgit-secret v1
  group: dev
  recipient: SHA256:...            (one per key, sorted)
  -----BEGIN AGE ENCRYPTED FILE-----
  ...
  -----BEGIN SSH SIGNATURE-----    (namespace fullgit-secret)
  ...
  ```

  Encrypted with **age** to every current key of every member of the
  group. age doesn't authenticate senders, and the group's public keys are
  public, so anyone with push access could otherwise replace a secret with
  their own. A sealed file is therefore only opened if its signer is a
  member of the group or an owner, and a clone refuses to seal for a
  group its user may not write.
- Implemented as a git filter using the long-running
  `filter.fullgit.process` protocol (one process per git command), with
  `filter.fullgit.required=true`: if sealing fails, `git add` fails rather
  than storing plaintext.
  - **clean** seals. age output is randomized, so if the plaintext matches
    what the index holds, the index blob is returned unchanged; otherwise
    every `git status` would report changes.
  - **smudge** verifies and decrypts. When it can't (not a recipient, no
    key, untrusted signer, policy not synced yet) it checks out the sealed
    file unchanged and says why; it never fails a checkout.
    `fullgit secret checkout` retries once that is fixed.
- A `diff=fullgit` textconv driver gives plaintext diffs locally.
- Decryption needs the private key file: ssh-agent can sign but not
  decrypt. It is `fullgit.identityFile`, else `user.signingkey` without
  `.pub`. Passphrase-protected keys are unlocked once per git command.
- Guards, installed by `fullgit init`: a `pre-commit` hook refuses staged
  secrets that aren't sealed (e.g. added while the filter wasn't set up),
  and a `pre-push` hook refuses commits that hold one, which catches
  `--no-verify`. `fullgit doctor` checks the whole setup.
- `fullgit secret rekey` reseals, in the index, secrets whose recipients
  differ from their group's current keys. It names everyone who could read
  the previous version, because git history still holds it: those values
  must be **rotated**.
- `fullgit secret list` shows each secret's group and whether it is sealed,
  trusted, current and readable by you.
- Limits: a clone without fullgit set up (no filter, no hooks) can still
  commit plaintext; only a server-side check catches that (Phase 7). The
  signature doesn't cover the path, so one secret of a group can be swapped
  for another of the same group.

## Per-user files

- Declared with the `fullgit-local` attribute and ignored by git;
  `fullgit local add <path>` writes both:

  ```
  # .gitattributes             # .gitignore
  /mise.local.toml fullgit-local   /mise.local.toml
  ```

  Hand-written patterns (`*.local.toml fullgit-local`) work too, in the root
  `.gitattributes` or `$GIT_DIR/info/attributes`.
- **One snapshot per user**, not per branch. `fullgit local save` packs the
  declared files into one archive, encrypts it to the user's current keys
  (all their devices), and appends it as a signed `local.save {sealed,
  recipients}` operation to `refs/fullgit/users/<identity>/local`. One
  archive hides the file names too. Only operations signed by a key of that
  identity count; anything else on the ref is ignored. Earlier snapshots stay
  in the ref's history: `fullgit local log`, `restore --from <id>`.
- Each clone records in `$GIT_DIR/fullgit/local.json` the ref head it last
  saved to or restored from (its *base*) and what that snapshot held:
  - `save` refuses if the ref moved past the base (another device saved),
    unless `--force`. Concurrent saves that meet in `sync` merge like any
    entity; the later one in replay order is current, and both devices are
    then behind.
  - `restore` overwrites a file only if it is unchanged since the base,
    unless `--force`; otherwise it reports a conflict and keeps the base.
    Files missing locally are written; local files the snapshot lacks are
    left alone (deletions don't propagate).
  - `save` is a no-op when nothing changed, unless the identity's keys did:
    saving after adding a device's key re-encrypts for it.
- Hooks: `pre-push` saves when the files changed and pushes the snapshot
  ref (pushes of `refs/fullgit/*` alone don't, so `sync` doesn't recurse).
  `pre-commit` and `pre-push` refuse per-user files in commits. `fullgit sync`
  says when another device saved; restoring is explicit, as it may prompt
  for the key's passphrase. A `post-checkout` hook was planned for fresh
  clones, but hooks only exist after `fullgit init`, so `sync` points there
  instead.
- Limits: per-user files inside directories git ignores wholesale are still
  found (`git ls-files --others`), but the lookup walks them, so huge ignored
  trees slow `local` commands and `git push` down. A removed key can still
  open the snapshots saved before its removal; only later ones exclude it.

## Issues

- State: title, description, author, status (open/closed), labels,
  assignees, comments, and a timeline of what happened.
- Ops: `issue.create {title, body, labels?}`, `issue.edit {title?, body?}`,
  `issue.comment {body}`, `issue.comment_edit {comment, body}`,
  `issue.label {add?, remove?}`, `issue.assign {add?, remove?}`,
  `issue.status {status}`.
- Permissions: contributors open issues and comment. The author or a
  maintainer edits, labels, assigns, closes and reopens. A comment is edited
  only by its author. Losing a role (a revoke) stops further operations;
  those the revoker had seen stay.
- Concurrency: operations that change nothing (closing a closed issue) are
  accepted, since concurrent ones overlap; replay order settles the rest,
  e.g. one clone adding a label another removed.
- Issues are named by a prefix of their id (`db1f1417`). Sequential numbers
  would need coordination a dumb host can't provide.
- CLI: `fullgit issue new/list/show/comment/edit/edit-comment/close/reopen/
  label/assign`; text comes from flags or git's editor. Nothing is shared
  until `fullgit sync`.
- Times are commit times, from each author's clock.

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
| 3. Secrets | Filter driver, age, guards, `rekey` | done (2026-10-17) |
| 4. Per-user files | `local add/save/restore`, hooks | done (2026-10-17) |
| 5. Issues | CLI: create, list, show, comment, close | done (2026-10-17) |
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
