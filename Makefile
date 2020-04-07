
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
	@cat build/CMakeCache.txt  | grep -q HAVE_JIT.*yes && cd tests && btest -j -f diag.log
	@cat build/CMakeCache.txt  | grep -q HAVE_JIT.*no && cd tests && btest -j -g no-jit -f diag.log

test-core:
	@cd tests && btest -j -g spicy-core -f diag.log

clean:
	@if [ -e build/Makefile ]; then $(MAKE) -C build clean; else true; fi
	@if [ -e build/build.ninja ]; then ninja -C build clean; else true; fi

real-clean:
	rm -rf build

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
