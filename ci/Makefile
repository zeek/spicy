# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

# Helper for building Docker image locally for testing.

all:

build:
	DOCKER_BUILDKIT=1 docker build --build-arg "UID=$$(id -u)" --build-arg "GID=$$(id -g)" -t spicy-ci:latest .

run:
	docker run -v $$(cd .. && pwd):/opt/spicy -w /opt/spicy --cap-add SYS_PTRACE --security-opt seccomp=unconfined -i -t spicy-ci:latest /bin/bash
