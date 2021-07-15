#!/bin/sh

echo "Preparing FreeBSD environment"
sysctl hw.model hw.machine hw.ncpu
set -e
set -x

# Detection of whether we run in the build directory requires `/proc`.
echo "proc /proc procfs rw,noauto 0 0" >> /etc/fstab
mount /proc

env ASSUME_ALWAYS_YES=YES pkg bootstrap
pkg install -y bash git cmake flex bison python3 ninja llvm11 base64 ccache

pyver=$(python3 -c 'import sys; print(f"py{sys.version_info[0]}{sys.version_info[1]}")')
pkg install -y "$pyver"-pip
pip install btest
