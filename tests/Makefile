
all: test-build

# Shortcuts used from the top-level Makefile.
test: test-build
test-analyzers: test-analyzers-build
test-all: test-build test-analyzers-build

# Run tests from the build directory. Defaults to "ROOT/build", set SPICY_BUILD_DIRECTORY to change.
test-build:
	@btest -j -d

# Runs analyzer tests from the build directory.
test-analyzers-build: _check-zeek _build-spicy-analyzers
	@cd $$(Scripts/build-directory) && $(MAKE) -C ../zeek/spicy-analyzers/tests

# Runs tests from the installation prefix. May need to have SPICY_INSTALLATION_DIRECTORY set.
test-install:
	@btest -j -d -a installation

_check-zeek:
	@PATH=$$(Scripts/build-directory)/bin:$${PATH} ./Scripts/have-zeek-plugin || exit 1

_build-spicy-analyzers:
	@cd $$(Scripts/build-directory); \
		if [ -e Makefile ]; then $(MAKE) -j spicy-analyzers; else true; fi; \
		if [ -e build.ninja ]; then ninja spicy-analyzers; else true; fi;

clean:
	@rm -f .btest.failed.dat
	@rm -rf .tmp
	@$(MAKE) -C ../zeek/analyzers/tests clean

.PHONY: all test-build test-install test-analyzers test-analyzers-build _build-spicy-analyzers _check-zeek
