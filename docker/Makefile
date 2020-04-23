
all: help

help:
	@echo
	@echo 'Run "make build-<platform>", then optionally "make test-<platform>",'
	@echo 'and finally "make run-<platform>".'
	@echo
	@echo Available platforms:
	@echo
	@cat Makefile | awk -F '[-:]' '/^build-/ { printf("    %s-%s\n", $$2, $$3); }' | sort
	@echo

build-ubuntu-19.10:
	./docker-helper build ubuntu-19.10

test-ubuntu-19.10: build-ubuntu-19.10
	./docker-helper test ubuntu-19.10

run-ubuntu-19.10:
	./docker-helper run ubuntu-19.10

build-alpine-3.11:
	./docker-helper build alpine-3.11

test-alpine-3.11: build-alpine-3.11
	./docker-helper test alpine-3.11

run-alpine-3.11:
	./docker-helper run alpine-3.11

build-centos-8:
	./docker-helper build centos-8

test-centos-8: build-centos-8
	./docker-helper test centos-8

run-centos-8:
	./docker-helper run centos-8
