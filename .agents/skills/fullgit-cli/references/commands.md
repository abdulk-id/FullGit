# `fullgit` command reference

Everything below is verified against the CLI in `crates/fullgit` (v0.0.1).
`fullgit help <command>` prints the same thing at runtime.

## Top level

| Command                                                  | What it does                                                                                                                                                        |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fullgit init [remote]`                                  | Fetch `refs/fullgit/*` from the remote, trust the policy named by the committed `.fullgit/root`, install the secret filter and the `pre-commit` / `pre-push` hooks. |
| `fullgit sync [remote]`                                  | Fetch, merge and push all `refs/fullgit/*` with the remote. The only command that shares anything.                                                                  |
| `fullgit doctor`                                         | Check the clone's setup: hooks, filters, keys, policy, secrets, per-user files.                                                                                     |
| `fullgit verify [branch] [--remote R]`                   | List every commit on a protected branch that did not come through a pull request. Exits 1 if there are any.                                                         |
| `fullgit web [--port N] [--no-open] [--remote R]`        | Serve the clone at `127.0.0.1` with a browser UI.                                                                                                                   |
| `fullgit github import [--remote R] [--repo owner/name]` | Copy a GitHub repository's issues and pull requests into this clone. One way: nothing is written back. Needs `gh` installed and logged in.                          |
| `fullgit help [command]`                                 | Usage for any command.                                                                                                                                              |

## `fullgit id` — identities and keys

| Command                                    | What it does                                                                                                                                                            |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fullgit id create [--name N] [--email E]` | Create an identity for your signing key (git's `user.signingkey`). Defaults to git's `user.name` / `user.email`.                                                        |
| `fullgit id show [who]`                    | Show one identity, its role and its keys. `who` defaults to `me`.                                                                                                       |
| `fullgit id list`                          | List all identities and their roles.                                                                                                                                    |
| `fullgit id edit [--name N] [--email E]`   | Change your own name or email.                                                                                                                                          |
| `fullgit id add-key [key] [--proof file]`  | Add a key to your identity, e.g. for another machine. With a key path, it proves itself; with `--proof`, use the output of `fullgit id prove` run on the other machine. |
| `fullgit id prove <identity>`              | Print a key and a proof that `fullgit id add-key --proof` accepts on a machine holding it.                                                                              |
| `fullgit id remove-key <key\|fingerprint>` | Remove a key from your identity. Operations it already signed stay yours.                                                                                               |

Identities are named by `me`, an email address, or an id prefix.

## `fullgit policy` — who may do what

| Command                                                                    | What it does                                                                                           |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `fullgit policy init [--owner who]`                                        | Create the policy with you as owner. Writes `.fullgit/root` for you to commit.                         |
| `fullgit policy show`                                                      | Show roles, groups, branch rules and labels.                                                           |
| `fullgit policy grant <who> <role>`                                        | Give an identity a role: `reader`, `contributor`, `maintainer` or `owner`.                             |
| `fullgit policy revoke <who>`                                              | Take away a role. Operations they signed that this clone already saw stay valid.                       |
| `fullgit policy group add\|remove <group> <who>`                           | Manage named groups, e.g. who can read a secret.                                                       |
| `fullgit policy protect <branch> [--approvals N] [--group G] [--remote R]` | Require N approvals to merge pull requests into a branch. `--approvals 0` is refused; use `unprotect`. |
| `fullgit policy unprotect <branch>`                                        | Remove a branch's merge rule.                                                                          |
| `fullgit policy label add\|remove <label>...`                              | Manage the labels issues may carry. Maintainers may too.                                               |
| `fullgit policy label describe <label> <description>`                       | Record what a label is for; an empty description clears it.                                            |

Only owners change the policy, except labels, which maintainers manage too.

## `fullgit issue` — issues

| Command                                                                               | What it does                                                          |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `fullgit issue new [-t title] [-m body] [-l label]...`                                | Open an issue. Without `-t`, opens your editor.                       |
| `fullgit issue list [--closed] [--all] [-l label]... [--assignee who] [--author who]` | List issues, open ones by default, most recently updated first.       |
| `fullgit issue show <id>`                                                             | Show an issue with its comments and history.                          |
| `fullgit issue comment <id> [-m body]`                                                | Comment. Without `-m`, opens your editor.                             |
| `fullgit issue edit <id> [--title T] [--body B]`                                      | Change title or description. With neither, opens your editor on both. |
| `fullgit issue edit-comment <id> <comment> [-m body]`                                 | Edit one of your comments.                                            |
| `fullgit issue close <id> [-m comment]`                                               | Close an issue.                                                       |
| `fullgit issue reopen <id> [-m comment]`                                              | Reopen an issue.                                                      |
| `fullgit issue label <id> <label>... [--remove label]...`                             | Add or remove labels. Labels must be ones the policy lists.           |
| `fullgit issue assign <id> <who>... [--remove who]...`                                | Assign or unassign people (`me`, an email or an id prefix).           |

`--closed` and `--all` conflict. Issues are named by the shortest unique prefix of their id (at least 4 hex chars).

## `fullgit pr` — pull requests

| Command                                                                                            | What it does                                                                                                                        |
| -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `fullgit pr new [-t title] [-m body] [--source branch] [--target branch] [--remote R]`             | Open a pull request. The current branch into the remote's default branch by default. Without `-t`, opens your editor.               |
| `fullgit pr list [--closed] [--merged] [--all] [--author who]`                                     | List pull requests, open ones by default, most recently updated first. Shows the review state.                                      |
| `fullgit pr show <id>`                                                                             | Show revisions, comments, reviews, and whether it may be merged.                                                                    |
| `fullgit pr diff <id> [-r revision] [--since revision]`                                            | Show a revision's changes, or what changed between revisions. `-r`/`--revision` is 1-based; the latest by default.                  |
| `fullgit pr checkout <id> [--branch name]`                                                         | Switch to a branch at the pull request's latest revision.                                                                           |
| `fullgit pr revise [id] [-m note] [--head rev] [--remote R]`                                       | Record the source branch's new commits as the next revision. Without an id, revises your open pull request from the current branch. |
| `fullgit pr comment <id> [-m body] [--file path --line N [--old] [-r revision]] [--reply comment]` | Comment on the pull request, on a line, or in a comment's thread. `--line` is in the old file with `--old`.                         |
| `fullgit pr edit-comment <id> <comment> [-m body]`                                                 | Edit one of your comments.                                                                                                          |
| `fullgit pr edit <id> [--title T] [--body B]`                                                      | Change the title or description.                                                                                                    |
| `fullgit pr review <id> (--approve \| --request-changes) [-m body]`                                | Review the latest revision. Requesting changes without `-m` opens your editor.                                                      |
| `fullgit pr close <id> [-m comment]`                                                               | Close without merging.                                                                                                              |
| `fullgit pr reopen <id> [-m comment]`                                                              | Reopen.                                                                                                                             |
| `fullgit pr merge <id> [--remote R]`                                                               | Merge the latest revision into the target on the remote, if the branch's rule allows it. Syncs before and after. Maintainers only.  |

## `fullgit secret` — encrypted files

| Command                                    | What it does                                                                                                         |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| `fullgit secret add --group <g> <path>...` | Mark files as secrets of a policy group in `.gitattributes`. `git add` them as usual; they are sealed on the way in. |
| `fullgit secret list`                      | List secrets and whether they are sealed, current and readable by you.                                               |
| `fullgit secret rekey <path>...`           | Reseal secrets to their group's current keys, e.g. after someone left. Stages the result; commit it.                 |
| `fullgit secret checkout`                  | Decrypt secrets still sealed in the working tree, e.g. after `fullgit init` or after joining a group.                |

The `pre-commit` and `pre-push` hooks refuse to commit or push a secret that
isn't encrypted.

## `fullgit local` — per-user files

| Command                                         | What it does                                                                                                           |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `fullgit local add <path>...`                   | Mark files as per-user: ignored by git, kept in your own encrypted snapshot. Writes `.gitattributes` and `.gitignore`. |
| `fullgit local list`                            | List per-user files, and whether they changed since you last saved.                                                    |
| `fullgit local save [--force]`                  | Save your per-user files as your new snapshot, encrypted to all your keys. `git push` does this too.                   |
| `fullgit local restore [--force] [--from <id>]` | Write your snapshot's files into the working tree. Never overwrites a file you changed unless `--force`.               |
| `fullgit local log`                             | Your snapshots, newest first.                                                                                          |

## `fullgit debug` — low level

| Command                                                  | What it does                                                                                                                          |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `fullgit debug log <refname>`                            | Print an entity's operations in replay order. `refname` is a full ref or one relative to `refs/fullgit/` (e.g. `issues/9fed2afd...`). |
| `fullgit debug append <refname> <kind> [--payload json]` | Append a signed operation to an entity ref. Writes raw operations, bypassing the model and the permission checks. Debugging only.     |

## Exit statuses worth knowing

- `fullgit verify` exits 1 when a protected branch has commits that did not come through a pull request.
- `fullgit doctor` exits 1 when a check fails (as opposed to warns).
- `fullgit secret rekey` exits 1 when a secret could not be resealed.
- `fullgit local restore` exits 1 on a conflict between your copy and the snapshot.
- Every command that needs a signing key fails when `user.signingkey` is unset or the key is locked.
