#!/bin/sh

set -e

cd "$(git rev-parse --show-toplevel)" || exit 1

TARBALL=spicy.tar

# Create archive for the main repo.
rm -f "$TARBALL"
git archive -o "${TARBALL}" HEAD

# Add all submodules to archive.
git submodule foreach --quiet 'cd $toplevel && tar rf '"${TARBALL}"' $sm_path'

# Add a VERSION file to the archive.
./scripts/autogen-version --store
tar rf "${TARBALL}" VERSION

# Compress archive.
bzip2 -9 "${TARBALL}"
