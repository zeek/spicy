#!/usr/bin/env python3

import multiprocessing
import os
import subprocess


IMAGE = "spicy-fuzz"
OUT = os.getcwd() + "/spicy-fuzz"

MAX_TOTAL_TIME = 600

# Build base Docker image.
subprocess.check_call(["docker", "build", "-t", IMAGE, "."])

# Create fuzzing binaries.
try:
    os.mkdir(OUT)
except FileExistsError:
    pass

subprocess.check_call(["docker", "run", "-it", "--rm",
                       "-v", OUT+":/out", "-e", "OUT=/out",
                       "-v", os.getcwd() + "/../..:/work",
                       "-e", "CXX=clang++-12",
                       "-e", "CC=clang-12",
                       "-e", "SANITIZER=address",
                       IMAGE,
                       "/work/ci/fuzz/build.sh",
                       ])

# Run individual fuzzers.
fuzzers = {
    "dhcp": ["Message"],
    "dns": ["Message"],
    "http": ["HTTP::Request", "HTTP::Requests", "HTTP::Reply", "HTTP::Replies"],
    "ipsec": ["IPSecPacketUDP", "IPSecPacketsTCP", "IPSecIKE"],
    "tftp": ["Packet"],
    "pe": ["ImageFile"],
    "PNG": ["File"],
    "wireguard": ["WireGuardPacket"],
}

for grammar, parsers in fuzzers.items():
    for parser in parsers:
        subprocess.check_call(["docker", "run", "-it", "--rm",
                               "-v", OUT + ":/work",
                               "-e", "SPICY_FUZZ_PARSER=" + parser,
                               IMAGE,
                               *"/work/fuzz-{grammar} -max_total_time={max_total_time} -jobs={nproc} -create_missing_dirs=1 -artifact_prefix=/work/corpus-fuzz-{grammar}-{parser}/artifacts/ /work/corpus-fuzz-{grammar}-{parser}".format(
                                   grammar=grammar,
                                   parser=parser,
                                   max_total_time=MAX_TOTAL_TIME,
                                   nproc=multiprocessing.cpu_count()).split(),
                               ])
