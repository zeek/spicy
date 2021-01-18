#!/bin/sh

# This script runs the upstream benchmarks and produces a file
# $SPICY_BENCHMARK_DIR/report.txt.
#
# All dependencies are cached and kept up to date in $SPICY_BENCHMARK_DIR.

set -e

exec 2>&1

SPICY_BENCHMARK_DIR=$HOME/spicy-benchmark

# Update Spicy sources.
echo "Updating Spicy sources"
if [ ! -d "${SPICY_BENCHMARK_DIR}" ]; then
	git clone https://github.com/zeek/spicy --recursive "${SPICY_BENCHMARK_DIR}"
fi
cd "${SPICY_BENCHMARK_DIR}" || exit
git pull
git submodule update --init --recursive

# Update benchmark inputs.
echo "Updating benchmark inputs"
SPICY_BENCHMARK_DATA=spicy-benchmark-m57.tar.xz
curl --silent --show-error -L --remote-name-all -z "${SPICY_BENCHMARK_DATA}" https://download.zeek.org/data/"${SPICY_BENCHMARK_DATA}"
SPICY_BENCHMARK_DATA_DIR=$PWD/$(basename ${SPICY_BENCHMARK_DATA} .tar.xz)
rm -rf "${SPICY_BENCHMARK_DATA_DIR}"
tar xf "${SPICY_BENCHMARK_DATA}"

# Build Spicy.
echo "Building Spicy"
export CXX=/opt/clang10/bin/clang++
export CC=/opt/clang10/bin/clang
export ASM=${CC}
rm -rf build
./configure --enable-ccache --with-zeek=/data/zeek-3.2.3/ --build-type=Release --generator=Ninja
ninja -C build

# Build benchmark.
echo "Building benchmark"
cd build || exit
"${SPICY_BENCHMARK_DIR}"/scripts/run-benchmarks build

# Run benchmarks.
echo "Running benchmarks"
for benchmark in short long; do
	"${SPICY_BENCHMARK_DIR}"/scripts/run-benchmarks -t "${SPICY_BENCHMARK_DATA_DIR}"/$benchmark run | tee "${SPICY_BENCHMARK_DIR}"/$benchmark.log
done
"${SPICY_BENCHMARK_DIR}"/build/bin/hilti-rt-fiber-benchmark | tee "${SPICY_BENCHMARK_DIR}"/fiber.log

# Generate a report.
echo "Generating benchmark report"
SPICY_BENCHMARK_REPORT=${SPICY_BENCHMARK_DIR}/report.txt
rm -f "${SPICY_BENCHMARK_REPORT}"
(
	echo "Version: $(./bin/spicy-config --version)"
	echo "Date: $(date)"
	for benchmark in short long fiber; do
		echo ""
		echo "Benchmark: $benchmark"
		echo "---------------------"
		cat "${SPICY_BENCHMARK_DIR}"/$benchmark.log
	done
) >"${SPICY_BENCHMARK_REPORT}"
