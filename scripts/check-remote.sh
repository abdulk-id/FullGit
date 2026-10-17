#!/usr/bin/env bash
# Phase 0 host check: does a git host accept, keep and serve refs/fullgit/*?
#
# Usage: scripts/check-remote.sh <remote-url> [--keep]
#
# Point it at an EMPTY THROWAWAY repository. It pushes one signed operation to
# refs/fullgit/issues/spike-<timestamp>, fetches it back through a fresh
# clone, verifies it, and then deletes the ref unless --keep is given. It
# signs with a temporary key, so your own keys and ssh-agent are not used.
set -euo pipefail

url=${1:?usage: $0 <remote-url> [--keep]}
keep=${2:-}
root=$(cd "$(dirname "$0")/.." && pwd)
fullgit=${FULLGIT:-$root/target/debug/fullgit}
[[ -x $fullgit ]] || (cd "$root" && cargo build -q -p fullgit)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
ref="issues/spike-$(date +%s)"

ssh-keygen -q -t ed25519 -N "" -C spike@fullgit -f "$tmp/key"

echo "==> writing a signed operation"
git init -q "$tmp/writer"
cd "$tmp/writer"
git config user.name "fullgit spike"
git config user.email spike@fullgit
git config user.signingkey "$tmp/key"
git remote add origin "$url"
id=$("$fullgit" debug append "$ref" issue.create --payload '{"title":"host check"}')
echo "    $id"

echo "==> syncing refs/fullgit/*"
"$fullgit" sync origin

echo "==> listing remote refs"
git ls-remote origin 'refs/fullgit/*'

echo "==> fetching from a fresh clone"
git clone -q "$url" "$tmp/reader" 2>/dev/null || { git init -q "$tmp/reader" && git -C "$tmp/reader" remote add origin "$url"; }
cd "$tmp/reader"
"$fullgit" init origin
git fetch -q origin
fetched=$(git rev-parse "refs/remotes/origin/fullgit/$ref")
[[ $fetched == "$id" ]] || { echo "FAIL: fetched $fetched, expected $id"; exit 1; }
"$fullgit" debug log "refs/remotes/origin/fullgit/$ref"

echo "==> git verify-commit"
echo "spike@fullgit $(cat "$tmp/key.pub")" > "$tmp/allowed_signers"
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$tmp/allowed_signers" verify-commit "$id"

if [[ $keep != --keep ]]; then
    echo "==> deleting the test ref from the remote"
    git -C "$tmp/writer" push -q origin ":refs/fullgit/$ref"
fi

echo "PASS: $url keeps and serves refs/fullgit/*"
