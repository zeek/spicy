#!/usr/bin/env python3

import sys
import re

for f in sys.argv[1:]:
    with open(f) as input:
        if not any(
            map(
                lambda x: re.match(r".*Copyright.*by\ the\ Zeek\ Project", x),
                input.readlines(),
            )
        ):
            print(f"{f} does not seem to contain a license header")
            sys.exit(1)
