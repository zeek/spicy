# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

all: build

.PHONY: build doc

build:
	cmake --build build/

install:
	cmake --build build/ --target install

doc:
	$(MAKE) -C doc

test:
	$(MAKE) -C tests test

tidy:
	./scripts/run-clang-tidy -j 10 build

tidy-fixit:
	./scripts/run-clang-tidy -j 10 --fixit build

check: test format tidy
