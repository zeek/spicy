#!/bin/bash

# This script updates the zeekurity Spicy dockerhub images to the latest git version.
#
# NOTE: Users must adjust the file and point the env var DOCKER_PASSWORD_FILE
# to the path of a file containing the cleartext password of the zeekurity
# dockerhub account.

set -e

exec 2>&1

DIR=$(mktemp --tmpdir -d spicy_update_dockerhub.XXXXXX)
# shellcheck disable=SC2064
trap "rm -rf ${DIR}" EXIT

pushd "${DIR}"
git clone --recurse-submodules https://github.com/zeek/spicy.git
pushd spicy/docker
DOCKER_USERNAME=zeekurity DOCKER_PASSWORD_FILE=PASSWORD_FILE make -j 1 update_dockerhub
