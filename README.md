# FullGit

Issues, PRs, Secrets. Moving with the codebase

FullGit stores issues and their discussions, pull requests with their reviews, who may do what, the encrypted `.env`
your team shares, and your local files like `mise.local.toml` inside the git repository. It works offline, moves with
the repository and nothing lives in a git host's database.

## What travels with the repository

| What | How |
| ---- | --- |
| **Permissions** | Owners, maintainers, contributors and readers. Every change is signed with your SSH key, and every clone checks who was allowed to make it. Branch rules require approvals before merging. |
| **Issues** | Comments, labels, assignees, open/closed. |
| **Pull requests** | Revisions, line comments, approvals and requests for changes, merging. The reviewed commits travel too, so the branch doesn't need pushing. |
| **Secrets** | Files such as `.env`, committed encrypted to a group of people. Members see plain text in their working tree; everyone else, and the host, sees ciphertext. |
| **Per-user files** | Files such as `mise.local.toml`: never committed, but saved encrypted to you alone, so each of your machines gets your copy. |

All of it is stored as signed git commits under `refs/fullgit/*`, next to existing branches.

---

## Install

You need:

- Rust 1.88 or newer, and a C compiler (libgit2 is built in)
- git 2.38 or newer
- OpenSSH, and an **ed25519** SSH key (RSA and ECDSA keys aren't supported yet)
- Linux or macOS

From a clone of this repository:

```sh
cargo install --path crates/fullgit --locked
```

On Arch Linux, build a package from `master` instead:

```sh
cd packaging/arch
makepkg --install --savedeps
```

Otherwise, to also run it as `git fullgit`, link it under that name:

```sh
ln -s "$(command -v fullgit)" "$(dirname "$(command -v fullgit)")/git-fullgit"
```

fullgit signs with the key git signs commits with. If you haven't set one, point git at your public key, and load the
key into `ssh-agent`:

```sh
ssh-keygen -t ed25519                  # if you have no ed25519 key yet
git config --global user.signingkey ~/.ssh/id_ed25519.pub
ssh-add ~/.ssh/id_ed25519
```

## Getting started

### Set up a repository

The first person creates an identity and the policy, which makes them the owner. Issues and pull requests need a
policy, so do this first, ideally right after `git init`:

```sh
fullgit init                           # in your clone; fetches fullgit's refs, installs hooks
fullgit id create                      # you, as git's user.name and user.email
fullgit policy init                    # writes .fullgit/root
git add .fullgit/root
git commit -m "Adopt fullgit"
git push
fullgit sync
```

`fullgit sync` fetches, merges and pushes fullgit's refs. Run it whenever you want to share your changes or see other
people's. Nothing else is shared automatically, except where noted below.

### Add people

Each person does this once in their clone:

```sh
fullgit init
fullgit id create
fullgit sync
```

Then an owner gives them a role, and syncs:

```sh
fullgit sync
fullgit policy grant bob@example.com contributor
fullgit sync
```

Roles:
- `owner` (also changes the policy).
- `maintainer` (also manages others' issues, merges)
- `contributor` (opens issues and pull requests, comments, reviews),
- `reader`,

`fullgit policy show` lists them. `fullgit id add-key` adds another machine's key to your identity.

### Issues

```sh
fullgit issue new -t "Sync loses ops" -m "Two clones pushing at once." -l bug
fullgit sync
fullgit issue list
fullgit issue show 6de2                # named by the shortest unique start of their id
fullgit issue comment 6de2 -m "Reproduced."
fullgit issue close 6de2
```

Leave out `-t` or `-m` and your editor opens.

### Pull requests

```sh
git switch -c retry
# ...commit...
fullgit pr new -t "Retry sync"         # from the current branch into the remote's default branch
fullgit sync
```

If fullgit doesn't know the remote's default branch (e.g. you created the repository by pushing to an empty one),
pass `--target master`.

A reviewer:

```sh
fullgit sync
fullgit pr list
fullgit pr diff da3f
fullgit pr comment da3f --file src/sync.rs --line 12 -m "Back off here?"
fullgit pr review da3f --request-changes -m "See the comment."
```

The author adds commits, then records them as the next revision:

```sh
fullgit pr revise -m "Back off between rounds"
fullgit sync
```

The reviewer sees what changed since they looked, approves, and a maintainer merges:

```sh
fullgit pr diff da3f --since 1
fullgit pr review da3f --approve
fullgit pr merge da3f                  # merges on the remote, pushes, and records it
git pull
```

To require approvals before merging into a branch:

```sh
fullgit policy protect master --approvals 1
```

A git host can't stop people with push access from pushing to `master` directly, so fullgit detects it instead.
`fullgit verify master` lists every commit since the branch was protected that didn't come through a pull request. Use
your host's branch protection alongside it where you can.

### Secrets

Secrets are encrypted to a policy group:

```sh
fullgit policy group add dev alice@example.com
fullgit policy group add dev bob@example.com
fullgit sync
fullgit secret add --group dev .env
git add .gitattributes .env            # encrypted on the way in
git commit -m "Dev secrets"
git push
```

Members of `dev` see `.env` in plain text after `git pull`. The repository and the host only ever hold ciphertext.
When someone joins a group, a member runs `fullgit secret rekey` and commits. The newcomer then runs
`fullgit secret checkout`. When someone leaves, `rekey` stops them reading new versions, but rotate the secrets
themselves: they could read the old ones.

The pre-commit and pre-push hooks refuse to commit or push a secret that isn't encrypted.

### Per-user files

```sh
fullgit local add mise.local.toml      # ignores it, and marks it as yours
git add .gitattributes .gitignore
git commit -m "Per-user mise config"
git push                               # also saves your per-user files
```

Each person's copy is saved encrypted to their own keys whenever they
`git push`. On another of your machines, after adding its key with
`fullgit id add-key`:

```sh
fullgit sync
fullgit local restore
```

`fullgit local restore` never overwrites a file you changed on that machine
unless you pass `--force`.

---

## Usage

### The CLI

`fullgit help` lists all commands, and `fullgit help <command>` explains each command.

### In the browser

```sh
fullgit web
```

Opens a local web UI with the overview, issues, pull requests, diffs with line comments, reviews and merging. It
serves only your machine, and only to whoever has the URL it prints.

If your key has a passphrase and isn't in `ssh-agent`, the page asks for it once. The server keeps the key unlocked in
memory until it stops, or until you press "Lock key".

### When something's off

```sh
fullgit doctor
```

Checks the clone's setup: hooks, filters, keys, the policy, secrets and per-user files.
If you move the `fullgit` binary, run `fullgit init` again, as the hooks and the secret filter record where it is.

## What fullgit can and can't promise

- **Changes are signed and checked.** A change signed by someone without the role for it is ignored by every clone.
  Anyone who can push to the host can push garbage, delete fullgit's refs, or rewind them; garbage is ignored, and
  every clone keeps a full copy that `fullgit sync` pushes back.
- **Reading is enforced by encryption only.** Issues and pull requests are readable by anyone who can read the
  repository. Only secrets and per-user files are encrypted.
- **Branch rules are detected, not enforced.** See `fullgit verify` above.
- **Clocks aren't trusted for ordering, but dates are shown as written.** Each change shows its author's clock.
- **Revoking someone** keeps what they did that you had already synced, and ignores the rest. Run `fullgit sync`
  before revoking.
