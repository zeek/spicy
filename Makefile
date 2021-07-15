
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

format:
	./scripts/run-clang-format

format-fixit:
	./scripts/run-clang-format --fixit

tidy:
	./scripts/run-clang-tidy -j 10 build

tidy-fixit:
	./scripts/run-clang-tidy -j 10 --fixit build
	./scripts/run-clang-format --fixit

check: test format tidy
