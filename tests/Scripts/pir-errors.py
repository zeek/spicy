# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

"""Run error-only fixtures through spicy-driver, preserving exception types and descriptions."""

import re
import runpy
import subprocess
import sys

spec = runpy.run_path("inputs.py")
for parser, label, data in spec["cases"]:
    for chunk in (0, 1):
        result = subprocess.run(
            ["spicy-driver", "-p", parser, "-i", str(chunk), sys.argv[1]],
            input=data,
            capture_output=True,
            check=False,
        )
        assert result.returncode != 0, (label, result.stdout, result.stderr)
        error = re.search(
            r"processing failed with exception of type ([^\n]*?): ([^\n]*)",
            result.stderr.decode(),
        )
        assert error, result.stderr
        assert error[1] == "spicy::rt::ParseError", error[1]
        assert not result.stdout, result.stdout
        suffix = "-chunked" if chunk else ""
        kind = "ParseError" if spec.get("typed") else "error"
        print(f"{label}{suffix} {kind}: {error[2]}")
