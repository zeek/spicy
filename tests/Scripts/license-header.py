#!/usr/bin/env python3

import re
import sys

for f in sys.argv[1:]:
    with open(f) as input:
        if not any(
            re.match(r".*Copyright.*by\ the\ Zeek\ Project", x)
            for x in input.readlines()
        ):
            print(f"{f} does not seem to contain a license header")
            sys.exit(1)
