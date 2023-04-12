#!/bin/sh

# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

set -e

cd "$(git rev-parse --show-toplevel)" || exit 1

TARBALL="${PWD}/spicy.tar"

# Create archive for the main repo.
rm -f "$TARBALL"
git archive -o "${TARBALL}" HEAD

# Add all submodules to archive.
git submodule foreach --quiet 'cd $toplevel && tar rf '"${TARBALL}"' $sm_path'

# Introduce a top-level `spicy` directory and compress the tarball.
SCRATCH=$(mktemp -d)
VERSION=$(cat VERSION)
mkdir "${SCRATCH}/spicy-${VERSION}"
(
    cd "${SCRATCH}/spicy-${VERSION}" &&
    tar xf "${TARBALL}" &&
    rm -f "${TARBALL}" &&
    cd .. &&
    tar czf "${TARBALL}.gz" "spicy-${VERSION}"
)
rm -rf "${SCRATCH}"
