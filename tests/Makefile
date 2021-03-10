
all: test-spicy-build

# Shortcuts
test: test-spicy-build
test-zeek: test-zeek-build
test-analyzers: test-analyzers-build

test-all: test-all-build
test-all-build: test-spicy-build test-zeek-build test-analyzers-build
test-all-install: test-spicy-install test-zeek-install test-analyzers-install

# Run tests from the build directory. Defaults to "ROOT/build", set SPICY_BUILD_DIRECTORY to change.
test-spicy-build:
	@btest -j -d

# Runs tests from the installation prefix. May need to have SPICY_INSTALLATION_DIRECTORY set.
test-spicy-install:
	@btest -j -d -a installation

# Runs Zeek plugin tests from the build directory.
test-zeek-build:
	@if ./Scripts/have-zeek-plugin; then \
		$(MAKE) -C ../zeek/spicy-plugin/tests test-build; \
	else \
	 	echo "Zeek plugin not available, cannot run plugin tests"; \
		false; \
	fi

# Runs Zeek plugin tests from the installation directory.
test-zeek-install:
	@if ./Scripts/have-zeek-plugin; then \
		$(MAKE) -C ../zeek/spicy-plugin/tests test-install; \
	else \
	 	echo "Zeek plugin not available, cannot run plugin tests"; \
		false; \
	fi

# Runs analyzer tests from the build directory.
# This will trigger building them if they haven't yet.
test-analyzers-build: _build-spicy-analyzers
	@if ./Scripts/have-zeek-plugin; then \
		$(MAKE) -C ../zeek/spicy-analyzers/tests test-build; \
	else \
	 	echo "Zeek plugin not available, cannot run analyzer tests"; \
		false; \
	fi

# Runs analyzer tests from the install directory
# This assumes they have built and installed.
test-analyzers-install:
	@if ./Scripts/have-zeek-plugin; then \
		$(MAKE) -C ../zeek/spicy-analyzers/tests test-install; \
	else \
	 	echo "Zeek plugin not available, cannot run analyzer tests"; \
		false; \
	fi

_build-spicy-analyzers:
	@if ./Scripts/have-zeek-plugin; then \
		cd $$(Scripts/build-directory); \
			if [ -e Makefile ]; then $(MAKE) -j build-spicy-analyzers; else true; fi; \
			if [ -e build.ninja ]; then ninja build-spicy-analyzers; else true; fi; \
	fi

clean:
	@rm -f .btest.failed.dat
	@rm -rf .tmp
	@$(MAKE) -C ../zeek/spicy-analyzers/tests clean
	@$(MAKE) -C ../zeek/spicy-plugin/tests clean

.PHONY: all test-build test-install test-analyzers test-zeek-build test-analyzers-build _build-spicy-analyzers
