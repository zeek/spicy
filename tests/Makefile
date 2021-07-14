
all: test-spicy-build

# Shortcuts
test: test-spicy-build
test-install: test-spicy-install

# Run tests from the build directory. Defaults to "ROOT/build", set SPICY_BUILD_DIRECTORY to change.
test-spicy-build:
	@btest -j -d

# Runs tests from the installation prefix. May need to have SPICY_INSTALLATION_DIRECTORY set.
test-spicy-install:
	@btest -j -d -a installation

clean:
	@rm -f .btest.failed.dat
	@rm -rf .tmp

.PHONY: all test-build test-install
