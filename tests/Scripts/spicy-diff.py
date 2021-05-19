#!/usr/bin/env python3
"""Platform-independent diff utility."""

import argparse
import difflib
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('file1', type=str)
parser.add_argument('file2', type=str)
args = parser.parse_args()

f1 = open(args.file1).readlines()
f2 = open(args.file2).readlines()

sys.stdout.writelines(difflib.unified_diff(
    f1, f2, fromfile=args.file1, tofile=args.file2))
