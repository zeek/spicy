#!/usr/bin/env python3
# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

"""Measure emission and uncached C++ compilation with the benchmark targets' actual flags.

Usage: measure-pir-compilation.py BUILD OUTPUT [--repetitions 5]
Requires compile_commands.json (CMAKE_EXPORT_COMPILE_COMMANDS=ON).
The output directory retains sources, objects, timing logs, commands, and results.json.
Compilation includes generated linker glue and compiler process startup, but excludes linking.
The C++ compiler runs directly, bypassing compiler launchers and ccache.
"""

import argparse
import json
import os
import shlex
import statistics
import subprocess
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("build", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--repetitions", type=int, default=5)
args = parser.parse_args()
if args.repetitions < 1:
    parser.error("repetitions must be positive")
build = args.build.resolve()
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=True)
sources = Path(__file__).resolve().parent
commands = json.loads((build / "compile_commands.json").read_text())
spicyc = str(build / "bin/spicyc")
compiler = shlex.split(
    next(
        x["command"]
        for x in commands
        if Path(x["file"]).name == "Benchmark_unit_vector_size_Benchmark.cc"
    )
)[0]


def flags_for(route):
    sample = (
        "Benchmark_unit_vector_size_Benchmark.cc"
        if route == "legacy"
        else "PIRBench_unit_vector_size__r__spicy_pir_backend.cc"
    )
    entry = next(x for x in commands if Path(x["file"]).name == sample)
    flags = shlex.split(entry["command"])[1:]
    # compile_commands omits CMake's compiler launcher, so no ccache is involved.
    for option in ("-o", "-c"):
        index = flags.index(option)
        del flags[index : index + 2]
    return flags


def run(command, log):
    with log.open("w") as stream:
        start = time.perf_counter()
        subprocess.run(command, cwd=build, check=True, stdout=stream, stderr=stream)
        return time.perf_counter() - start


results = []
for root in (
    "unit-vector-size",
    "unit-vector-lookahead",
    "unit-nested",
    "unit-bytes",
    "unit-switch",
    "regex",
):
    for route in ("legacy", "pir"):
        directory = output / root / route
        directory.mkdir(parents=True, exist_ok=True)
        options = (
            ["--experimental-pir", "--strict-public-api", "-W", "no-unused-field"]
            if route == "pir"
            else []
        )
        if route == "pir":
            proof = directory / "route.log"
            run(
                [
                    spicyc,
                    *options,
                    "-p",
                    "-D",
                    "spicy-pir",
                    str(sources / f"{root}.spicy"),
                ],
                proof,
            )
            text = proof.read_text()
            assert (
                "attached PIR-produced HILTI module" in text
                and "falling back" not in text
            ), proof
        emit = [
            spicyc,
            *options,
            "-R",
            "-x",
            str(directory / "parser"),
            str(sources / f"{root}.spicy"),
        ]
        flags = flags_for(route)
        emit_times, compile_times = [], []
        # One untimed emission warms the compiler and filesystem without caching C++ objects.
        run(emit, directory / "warmup.log")
        cpp = sorted(directory.glob("*.cc"))
        compile_commands = [
            [compiler, *flags, "-c", str(path), "-o", str(path.with_suffix(".o"))]
            for path in cpp
        ]
        (directory / "commands.json").write_text(
            json.dumps({"emit": emit, "compile": compile_commands}, indent=2) + "\n"
        )
        for iteration in range(args.repetitions):
            emit_times.append(run(emit, directory / f"emit-{iteration}.log"))
            compile_times.append(
                sum(
                    run(cmd, directory / f"compile-{iteration}-{i}.log")
                    for i, cmd in enumerate(compile_commands)
                )
            )
        row = {
            "root": root,
            "route": route,
            "emission_seconds": emit_times,
            "cpp_seconds": compile_times,
            "cpp_lines": sum(len(path.read_bytes().splitlines()) for path in cpp),
            "object_bytes": sum(path.with_suffix(".o").stat().st_size for path in cpp),
        }
        results.append(row)
        (output / "results.json").write_text(
            json.dumps(
                {
                    "build": str(build),
                    "compiler": compiler,
                    "optimizer_cfg_env": os.environ.get("HILTI_OPTIMIZER_ENABLE_CFG"),
                    "results": results,
                },
                indent=2,
            )
            + "\n"
        )
        print(
            f"{root:18} {route:6} emit={statistics.median(emit_times):.3f}s "
            f"C++={statistics.median(compile_times):.3f}s lines={row['cpp_lines']} objects={row['object_bytes']}",
            flush=True,
        )
