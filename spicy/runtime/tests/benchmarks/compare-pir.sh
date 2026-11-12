#!/usr/bin/env bash
# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
#
# Compare the legacy and PIR parsing benchmarks.
#
# Usage: compare-pir.sh [legacy-binary [pir-binary]]
#
# The binaries default to build/bin/spicy-rt-parsing-benchmark and
# build/bin/spicy-rt-parsing-pir-benchmark, relative to the current directory.
# Environment:
#   REPETITIONS  repetitions per benchmark (default 10)
#   OUTDIR       where the JSON results go (default: a temporary directory)
#
# Prints the median throughput per benchmark and size, and the PIR/legacy ratio.
# Then runs Google Benchmark's compare.py, which needs scipy and numpy. If those
# are missing, only the table is printed.

set -eu

legacy_bin=${1:-build/bin/spicy-rt-parsing-benchmark}
pir_bin=${2:-build/bin/spicy-rt-parsing-pir-benchmark}
repetitions=${REPETITIONS:-10}
outdir=${OUTDIR:-$(mktemp -d)}
compare_py="$(cd "$(dirname "$0")" && pwd)/../../../../3rdparty/benchmark/tools/compare.py"

mkdir -p "$outdir"
legacy_json="$outdir/legacy.json"
pir_json="$outdir/pir.json"

run() {
    "$1" --benchmark_repetitions="$repetitions" --benchmark_report_aggregates_only=true \
        --benchmark_format=json --benchmark_out="$2" --benchmark_out_format=json >/dev/null
}

run "$legacy_bin" "$legacy_json"
run "$pir_bin" "$pir_json"

python3 - "$legacy_json" "$pir_json" <<'PY'
import json
import sys


def medians(path):
    with open(path) as f:
        data = json.load(f)
    result = {}
    for b in data["benchmarks"]:
        if b.get("aggregate_name") != "median" or b.get("error_occurred"):
            continue
        if "bytes_per_second" in b:
            result[b["run_name"]] = b["bytes_per_second"]
    return result


def fmt(value):
    return "-" if value is None else f"{value / 1e6:.2f} MB/s"


legacy = medians(sys.argv[1])
pir = medians(sys.argv[2])
names = list(legacy) + [n for n in pir if n not in legacy]
width = max((len(n) for n in names), default=9)

print(f"{'benchmark':<{width}}  {'legacy':>14}  {'pir':>14}  {'pir/legacy':>10}")
for name in names:
    l, p = legacy.get(name), pir.get(name)
    ratio = f"{p / l:.2f}" if l and p else "-"
    print(f"{name:<{width}}  {fmt(l):>14}  {fmt(p):>14}  {ratio:>10}")
PY

if python3 -c "import numpy, scipy" 2>/dev/null; then
    python3 "$compare_py" benchmarks "$legacy_json" "$pir_json" ||
        echo "warning: compare.py failed" >&2
else
    echo "warning: numpy/scipy not available, skipping compare.py" >&2
fi
