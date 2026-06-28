#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo ">>> Generating .SRCINFO from PKGBUILD..."
makepkg --printsrcinfo > .SRCINFO

echo
echo ">>> Changes to be committed:"
git diff --stat PKGBUILD .SRCINFO
echo

read -r -p "Commit message: " msg

if [[ -z "$msg" ]]; then
    echo "Aborted: no commit message provided."
    exit 1
fi

git add PKGBUILD .SRCINFO
git commit -m "$msg"
git push

echo
echo ">>> Pushed to aur.archlinux.org"
