# Running the Test Suite

The Spicy test suite uses [BTest](https://github.com/zeek/btest). Tests are
organized under this `tests/` directory and executed via the `btest` command.

## Prerequisites

- A successful Spicy build (CMake/Ninja)
- [BTest](https://github.com/zeek/btest) installed (`pip install btest`)
- The build directory must contain `CMakeCache.txt` and compiled binaries

## Quick Start (Linux / macOS)

```bash
# From the repository root, assuming 'build/' is the build directory:
cd tests
btest -j -d
```

Or use the Makefile:

```bash
make -C tests test
```

By default, BTest looks for a `build/` directory relative to the repo root. If
your build directory is elsewhere, set `SPICY_BUILD_DIRECTORY`:

```bash
export SPICY_BUILD_DIRECTORY=/path/to/your/build
cd tests
btest -j -d
```

## Running Specific Tests

```bash
# Run a single test by its dotted name
btest hilti.hiltic.jit.hilti-cxx

# Run tests matching a pattern
btest spicy.types.unit.*

# Parallel execution with 5 jobs
btest -j 5

# Show diagnostics on failure
btest -d hilti.hiltic.jit.hilti-cxx
```

## BTest Configuration

The test configuration lives in `tests/btest.cfg`. Key settings:

- **TestDirs**: `hilti spicy ctest codebase`
- **Environment**: Paths, compilers, and tool locations are derived from the
  build directory automatically.
- **Alternatives**: Use `-a installation` to test against an installed prefix
  (requires `SPICY_INSTALLATION_DIRECTORY`).

## Windows

On Windows, BTest must be run from **Git Bash** (MSYS2 shell provided by Git
for Windows). The standard Windows command prompt and PowerShell are not
supported.

### Windows-Specific Requirements

- Git for Windows (provides Git Bash)
- Build with MSVC (cl.exe) via CMake/Ninja
- `HILTI_CXX_COMPILER_LAUNCHER` must be unset or empty (ccache is not used for
  test JIT compilation on Windows)
- `MSYS=disable_pcon` must be exported to avoid pseudo-console issues

### Running Tests on Windows

A setup script is provided at `tests/setup-windows-env.sh`. Open Git Bash and
source it:

```bash
cd /c/path/to/spicy/tests
source ./setup-windows-env.sh
btest -j 5
```

The script automatically:
- Locates the build directory relative to its own location
- Exports the required environment variables (`MSYS`, `HILTI_CXX_COMPILER_LAUNCHER`)

You can also override the build directory:

```bash
SPICY_BUILD_DIRECTORY="c:/my/build" source ./setup-windows-env.sh
btest -j 5
```

After sourcing, run btest normally:

```bash
btest -j 5                                    # all tests
btest -d hilti.hiltic.jit.hilti-cxx           # single test with diagnostics
btest spicy.types.unit.context-unit-refs      # specific test
```

### Manual Windows Setup

If you prefer to run BTest directly:

```bash
export MSYS=disable_pcon
export SPICY_BUILD_DIRECTORY="c:/path/to/build"
export HILTI_CXX_COMPILER_LAUNCHER=
cd /c/path/to/spicy/tests
btest -j 5
```

### Known Windows Considerations

- Test files are checked out with CRLF line endings when `core.autocrlf=true`.
  The batch file parser (`spicy-driver -F`) handles CRLF transparently.
- JIT-compiled `.hlto` files are Windows DLLs and cannot be shared across
  different build configurations.
- The `PATH` inside BTest is set to include the build's `bin/` directory plus
  the `Scripts/` directory.
