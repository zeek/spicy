#!/bin/sh

set -e

cd "$(git rev-parse --show-toplevel)" || exit 1

TARBALL="${PWD}/spicy.tar"

# Create archive for the main repo.
rm -f "$TARBALL"
git archive -o "${TARBALL}" HEAD

# Add all submodules to archive.
git submodule foreach --quiet 'cd $toplevel && tar rf '"${TARBALL}"' $sm_path'

# Add a VERSION file to the archive.
./scripts/autogen-version --store VERSION
tar rf "${TARBALL}" VERSION

# Introduce a top-level `spicy` directory and compress the tarball.
SCRATCH=$(mktemp -d)
VERSION=$(./scripts/autogen-version --short)
mkdir "${SCRATCH}/spicy-${VERSION}"
(
    cd "${SCRATCH}/spicy-${VERSION}" &&
    tar xf "${TARBALL}" &&
    rm -f "${TARBALL}" &&
    cd .. &&
    tar czf "${TARBALL}.gz" "spicy-${VERSION}"
)
rm -rf "${SCRATCH}"
