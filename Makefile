# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

all: build

.PHONY: build doc

build:
	@if [ -e build/Makefile ]; then $(MAKE) -C build; else true; fi
	@if [ -e build/build.ninja ]; then ninja -C build; else true; fi

install:
	@if [ -e build/Makefile ]; then $(MAKE) -C build install; else true; fi
	@if [ -e build/build.ninja ]; then ninja -C build install; else true; fi

doc:
	$(MAKE) -C doc

test:
	$(MAKE) -C tests test

tidy:
	./scripts/run-clang-tidy -j 10 build

tidy-fixit:
	./scripts/run-clang-tidy -j 10 --fixit build

check: test format tidy
