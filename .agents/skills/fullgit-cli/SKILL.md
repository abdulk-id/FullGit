---
name: FullGit CLI
description: Learn the `fullgit` CLI to read and write fullgit's issues, pull requests, policy, identities, secrets and per-user files. Use this skill when a task mentions a project's issues, PRs, reviews, approvals, labels, roles, groups or secrets, or when working in a repository that uses fullgit (including the FullGit source repository itself).
---

# The `fullgit` CLI

`fullgit` stores issues, pull requests, permissions, secrets and per-user files **inside a git repository**, as signed
commits under `refs/fullgit/*`. This skill is about driving that CLI.

## First: three different things named "fullgit"

Sort them out before running anything.

| Name                          | What it is                                                                     | Tools for it                                     |
| ----------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------ |
| `fullgit` (the command)       | the CLI, whose source is `crates/fullgit` in this repo                         | this skill                                       |
| **FullGit** (this repository) | the Rust workspace: `crates/fullgit` (CLI) and `crates/fullgit-core` (library) | `rg`, `git log`, `cargo test` — the normal tools |
| `refs/fullgit/*`              | fullgit's data, in any repository that uses it                                 | the `fullgit` CLI, **not** `git`                 |

This repository uses fullgit on itself, so both are in play at the same time. `crates/fullgit/src/commands/issue.rs`
is source code. `fullgit issue list` shows this project's real, live issues.

**When the task is about fullgit's own source code**, like "fix the PR merge conflict handling", "add a flag to
`fullgit issue list`", this skill does not apply. Use `rg` and `cargo`. This skill applies when the task is about the
_data_ fullgit stores: issues, pull requests, policy, identities, secrets, per-user files.

## The rule: read fullgit's data with fullgit

Never read fullgit's data with git. `refs/fullgit/issues/<id>` is not an issue, it is a chain of signed operation
commits. The issue is what you get after replaying those operations in order, applying the policy, discarding
operations the policy rejects, and resolving name abbreviations. Raw git output shows you a commit, not the thing.

These are wrong:

```sh
git log refs/fullgit/issues/9fed...          # raw operations, not the issue
git show refs/fullgit/issues/9fed...          # same
git cat-file -p refs/fullgit/issues/9fed:op.json
git for-each-ref refs/fullgit/                # storage layout, not meaning
git diff refs/fullgit/prs/...
```

These are right:

```sh
fullgit issue list
fullgit issue show 9fed
fullgit pr list
fullgit pr show da3f
fullgit policy show
fullgit id list
```

If you genuinely need the raw operations, such as while debugging the tool itself, use `fullgit debug log <refname>`,
which prints them in replay order. That is a debugging view, not a substitute for `fullgit issue show`.

### Ref layout (orientation only)

| Ref                                   | Holds                                             |
| ------------------------------------- | ------------------------------------------------- |
| `refs/fullgit/identities/<id>`        | one identity and its keys                         |
| `refs/fullgit/policy/<id>`            | the policy: roles, groups, branch rules, labels   |
| `refs/fullgit/issues/<id>`            | one issue's operations                            |
| `refs/fullgit/prs/<id>`               | one pull request's operations                     |
| `refs/fullgit/users/<identity>/local` | one person's encrypted per-user snapshot          |
| `refs/fullgit/code/<commit>`          | keeps a pull request's reviewed commits reachable |
| `refs/fullgit-remotes/<remote>/*`     | the remote's copy of the above, as fetched        |

`<id>` is the hex oid of the entity's root operation.

## Orient yourself before acting

```sh
fullgit doctor      # hooks, secret filter, keys, policy, secrets, per-user files
fullgit sync        # fetch + merge + push fullgit's refs with the remote
fullgit policy show # roles, groups, branch rules, labels
fullgit id list     # who is who, and their roles
```

`fullgit sync` is the only thing that shares anything. An issue you create is invisible to everyone else, and other
people's issues are invisible to you, until it runs. Run it first so you act on current data, and last so your work is
published.

## Quick reference

| I want to                                      | Run                                                                                                                               |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| See the open issues                            | `fullgit issue list`                                                                                                              |
| Read an issue and its comments                 | `fullgit issue show <id>`                                                                                                         |
| File an issue                                  | `fullgit issue new -t "Title" -m "Body"`                                                                                          |
| Comment / close / label / assign               | `fullgit issue comment <id> -m "..."`, `fullgit issue close <id>`, `fullgit issue label <id> bug`, `fullgit issue assign <id> me` |
| See the open pull requests                     | `fullgit pr list`                                                                                                                 |
| Read a pull request, its revisions and reviews | `fullgit pr show <id>`                                                                                                            |
| Read the code a pull request proposes          | `fullgit pr diff <id>`, `fullgit pr diff <id> --since 1`                                                                          |
| Check a pull request out                       | `fullgit pr checkout <id>`                                                                                                        |
| Open a pull request                            | `fullgit pr new -t "Title" -m "Body"`                                                                                             |
| Record new commits as a revision               | `fullgit pr revise -m "what changed"`                                                                                             |
| Review                                         | `fullgit pr review <id> --approve` / `--request-changes -m "why"`                                                                 |
| Comment on a line                              | `fullgit pr comment <id> --file src/sync.rs --line 12 -m "..."`                                                                   |
| Merge                                          | `fullgit pr merge <id>` (maintainers only)                                                                                        |
| Who may do what                                | `fullgit policy show`                                                                                                             |
| Give someone a role                            | `fullgit policy grant <email                                                                                                      | id> contributor` |
| Check branch protection                        | `fullgit verify [branch]`                                                                                                         |
| Secrets                                        | `fullgit secret list`, `fullgit secret add --group dev .env`, `fullgit secret rekey`, `fullgit secret checkout`                   |
| Per-user files                                 | `fullgit local list`, `fullgit local save`, `fullgit local restore`                                                               |
| Import from GitHub (one way)                   | `fullgit github import`                                                                                                           |

Full flags: `fullgit help <command>`, or `references/commands.md` in this skill's
directory.

## Names

- Issues and pull requests are named by the **shortest unique prefix of their id**, at least 4 hex characters: `9fed`,
  `da3f`. `fullgit issue list` and `fullgit pr list` print exactly the names to use.
- A prefix that matches several entities is an error. Pass more characters in that case.
- Identities are named by `me`, an email address, or an id prefix.
- Revisions are numbered from 1. `fullgit pr show` lists them.

## Non-interactive rules (you have no editor)

Several commands open `$GIT_EDITOR` when the text is missing. An agent has no editor, so always pass the text:

| Command                               | Always pass                          |
| ------------------------------------- | ------------------------------------ |
| `fullgit issue new`                   | `-t "title" -m "body"`               |
| `fullgit issue comment`               | `-m "body"`                          |
| `fullgit issue edit`                  | at least one of `--title` / `--body` |
| `fullgit issue edit-comment`          | `-m "body"`                          |
| `fullgit pr new`                      | `-t "title" -m "body"`               |
| `fullgit pr comment`                  | `-m "body"`                          |
| `fullgit pr edit`                     | at least one of `--title` / `--body` |
| `fullgit pr edit-comment`             | `-m "body"`                          |
| `fullgit pr review --request-changes` | `-m "why"` (approve needs no body)   |

`fullgit pr revise -m "note"` takes an optional note; pass one, it is what reviewers read.

## Issues and pull requests, end to end

Author:

```sh
git switch -c retry
# ...edit, commit...
fullgit pr new -t "Retry sync" -m "Back off between rounds"   # from the current branch
fullgit sync
```

Reviewer:

```sh
fullgit sync
fullgit pr list
fullgit pr diff da3f
fullgit pr comment da3f --file src/sync.rs --line 12 -m "Back off here?"
fullgit pr review da3f --request-changes -m "See the comment."
```

Author adds commits, then records them as the next revision:

```sh
# ...commit more...
fullgit pr revise -m "Back off between rounds"
fullgit sync
```

Reviewer looks at what changed since they last looked, approves, and a maintainer merges:

```sh
fullgit pr diff da3f --since 1
fullgit pr review da3f --approve
fullgit pr merge da3f     # merges on the remote, pushes, records it
git pull
```

Things that bite:

- `fullgit pr new` compares against the **remote's** default branch. If fullgit doesn't know it, pass
  `--target master`, or run `git remote set-head origin --auto`.
- `fullgit pr new` needs the source branch to have at least one commit the target doesn't.
- A review approves a **revision**. A new revision needs new approvals, and a request for changes blocks until that
  reviewer approves again.
- Merging takes a **maintainer**, and the target branch's rule (`fullgit policy show`).
- `fullgit pr merge` is the only fullgit command that pushes code to a branch.

## Secrets and per-user files

```sh
fullgit secret add --group dev .env
git add .gitattributes .env
git commit -m "Dev secrets"
git push
```

Members of `dev` see `.env` in plain text after `git pull`. The repository and the host only ever hold ciphertext.
When someone joins the group, a member runs `fullgit secret rekey` and commits; the newcomer runs
`fullgit secret checkout`. When someone leaves, `rekey` stops them reading _new_ versions — rotate the values, they
could read the old ones.

Per-user files (e.g. `mise.local.toml`) are ignored by git and kept in your own encrypted snapshot:

```sh
fullgit local add mise.local.toml
git add .gitattributes .gitignore
git commit -m "Per-user mise config"
git push                    # also saves your per-user files
```

On another of your machines, after `fullgit id add-key`: `fullgit sync`, then `fullgit local restore`.

## Where this repository's own issues live

This project tracks its work in fullgit: `fullgit issue list`, `fullgit issue show <id>`, `fullgit pr list`,
`fullgit pr show <id>`. The repository's GitHub issues are a separate thing; `fullgit github import` copies them one
way into fullgit (read-only from GitHub, never written back) and needs `gh` installed and logged in.

## Traps

- `git fetch` does fetch `refs/fullgit/*` — `fullgit init` added the refspec — but that only updates
  `refs/fullgit-remotes/<remote>/*`. It neither merges nor pushes. Use `fullgit sync`.
- `git push` does **not** push fullgit's refs. `fullgit sync` does.
- `git branch -a` does not show fullgit's refs, and should not, as they are not branches.
- Everything fullgit writes is **signed** with the SSH key in git's `user.signingkey` (ed25519). If it is unset,
  locked, or not in ssh-agent, the command fails. `fullgit doctor` says so.
- Issues and pull requests need a policy. `fullgit policy init` writes `.fullgit/root` for you to commit. Other clones
  trust it after `fullgit init`.
- Labels must be ones the policy lists (`fullgit policy show`).
- A local change is not shared until `fullgit sync`.
- Don't use `fullgit debug append` to write. It writes raw operations straight to a ref, bypassing the model and the
  permission checks, and can corrupt the entity. It exists for debugging the tool.
- `git fullgit ...` works too, when a `git-fullgit` symlink is on `PATH` (it is on this machine).
