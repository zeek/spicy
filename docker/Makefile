# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

all: help

help:
	@echo
	@echo 'Run "make build-<platform>", and then "make run-<platform>".'
	@echo
	@echo Available platforms:
	@echo
	@ls Dockerfile.* | sed 's/Dockerfile\./    /' | sort

build-%:
	./docker-helper build $*

run-%:
	./docker-helper run $*
