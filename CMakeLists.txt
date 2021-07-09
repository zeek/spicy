# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

cmake_minimum_required(VERSION 3.15.0)

project(spicy LANGUAGES ASM C CXX)

set(flex_minimum_version "2.6")
set(bison_minimum_version "3.0")
set(python_minimum_version "3.2")
set(macos_minimum_version "19.0.0") # macOS 10.15.0 (Catalina)

## Initialize defaults & global options

if ( NOT CMAKE_BUILD_TYPE )
    # CMake doesn't set build type by default.
    set(CMAKE_BUILD_TYPE "Debug")
endif ()

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

include(Util)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# CMake uses -O2 by default with RelWithDebInfo.
string(REPLACE "-O2" "-O3" CMAKE_CXX_FLAGS_RELWITHDEBINFO ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})

include(CheckCompiler)

include(GNUInstallDirs)
if (NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY )
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})
endif ()

if( NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY )
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
endif ()

if ( NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY )
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
endif ()

make_install_rpath(rpath ${CMAKE_INSTALL_FULL_BINDIR} ${CMAKE_INSTALL_FULL_LIBDIR})
set(CMAKE_INSTALL_RPATH "${rpath}")

if ( USE_CCACHE )
    find_program(CCACHE_PROGRAM ccache)
    if( CCACHE_PROGRAM )
        set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
        set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
    else ()
        set(USE_CCACHE "no (error: could not find ccache)")
    endif()
else ()
    set(USE_CCACHE "no")
endif ()

if ( USE_SANITIZERS )
    # Recommended flags per https://github.com/google/sanitizers/wiki/AddressSanitizer
    set(sanitizer_cxx_flags "-fsanitize=${USE_SANITIZERS} -fno-omit-frame-pointer -fno-optimize-sibling-calls -O1 -shared-libsan")
    set(sanitizer_ld_flags  "-fsanitize=${USE_SANITIZERS} -frtlib-add-rpath -shared-libsan")

   set(HILTI_HAVE_SANITIZER "yes" CACHE BOOL "Using sanitizer")
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${sanitizer_cxx_flags}")
   set(EXTRA_CXX_FLAGS "${EXTRA_CXX_FLAGS} ${sanitizer_cxx_flags}")
   set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${sanitizer_ld_flags}")
   set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${sanitizer_ld_flags}")
   set(EXTRA_LD_FLAGS "${EXTRA_LD_FLAGS} ${sanitizer_ld_flags}")

   set(HILTI_DEV_PRECOMPILE_HEADERS "no")
else ()
   set(HILTI_HAVE_SANITIZER "no" CACHE BOOL "Using sanitizer")
endif()

if ( USE_FUZZING )
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=fuzzer-no-link")
    set(EXTRA_CXX_FLAGS "${EXTRA_CXX_FLAGS} -fsanitize=fuzzer-no-link")
endif()

if ( USE_WERROR )
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${werror_flags}")
    set(EXTRA_CXX_FLAGS "${EXTRA_CXX_FLAGS} ${werror_flags}")
endif ()

## Load modules

# If the user specified dedicated prefixes for Flex or Bison, look in these
# prefixes first. As the upstream modules do not support specifying these we
# inject them here by hand.
#
# The implementation relies on the fact that the `find_*` commands do not search
# again should the output variable already be set successfully. We first search
# for the artifacts with `NO_DEFAULT_PATH` and then later trigger the upstream
# `find_package` logic. With that any user-specified prefix takes precedence
# over what could be found in the default search locations.
if ( FLEX_ROOT )
    find_program(FLEX_EXECUTABLE
                 NAMES flex win_flex
                 PATHS ${FLEX_ROOT}
                 PATH_SUFFIXES bin
                 NO_DEFAULT_PATH)
    find_library(FL_LIBRARY
                 NAMES fl
                 PATHS ${FLEX_ROOT}
                 PATH_SUFFIXES lib
                 NO_DEFAULT_PATH)
    find_path(FLEX_INCLUDE_DIR
              FlexLexer.h
              PATHS ${FLEX_ROOT}
              PATH_SUFFIXES include
              NO_DEFAULT_PATH)
endif ()

if ( BISON_ROOT)
    find_program(BISON_EXECUTABLE
                 NAMES bison win_bison
                 PATHS ${BISON_ROOT}
                 PATH_SUFFIXES bin
                 NO_DEFAULT_PATH)
endif ()

find_package(Python3)
find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Backtrace)

if ( Backtrace_FOUND AND NOT APPLE )
    # On systems other than MacOS there's a libexecinfo that's not working for us:
    # it seems to break when compiling without frame pointers so we disable it.
    if ( "${Backtrace_LIBRARY}" MATCHES "libexecinfo" )
        message(STATUS "Disabling backtrace because we found libexecinfo")
        set(Backtrace_FOUND "no")
    endif ()
endif ()

# Prettify output
if ( Backtrace_FOUND )
    set(HILTI_HAVE_BACKTRACE "yes")
else ()
    set(HILTI_HAVE_BACKTRACE "no")
endif ()

if ( APPLE )
    set(MACOS_FOUND "yes")
    require_version("maccOS" MACOS_FOUND ${CMAKE_SYSTEM_VERSION} "${macos_minimum_version}" true)
endif()

require_version("Python" Python3_FOUND Python3_VERSION "${python_minimum_version}" true)
require_version("Flex" FLEX_FOUND FLEX_VERSION "${flex_minimum_version}" true)
require_version("Bison" BISON_FOUND BISON_VERSION "${bison_minimum_version}" true)

find_package(GoldLinker)
find_package(Threads)

option(BUILD_TOOLCHAIN "Build the Spicy compiler toolchain" ON)

if ( BUILD_TOOLCHAIN )
    set(HAVE_TOOLCHAIN yes)
else ()
    set(HAVE_TOOLCHAIN no)
endif ()

# Set up testing infrastructure.
enable_testing()

# Add subdirectories.
add_subdirectory(hilti)
add_subdirectory(spicy)
add_subdirectory(scripts)
add_subdirectory(ci/fuzz)

option(BUILD_ZEEK_PLUGIN "Whether to build Zeek spicy-plugin and spicy-analyzers as submodules. Their preferred installation method is via 'zkg'." OFF)

if ( BUILD_ZEEK_PLUGIN )
    add_subdirectory(zeek)
else ()
    set(HAVE_ZEEK_PLUGIN "no" CACHE BOOL "" FORCE)
    # Quieten warnings about unused variables.
    set(_not_used "${SPICY_ZEEK_INSTALL_PLUGIN} ${ZEEK_ROOT_DIR}")
endif ()

add_subdirectory(3rdparty)

# Compute project version.
execute_process(COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/autogen-version --cmake --git-root ${CMAKE_CURRENT_SOURCE_DIR} --store ${PROJECT_SOURCE_DIR}/VERSION
    OUTPUT_VARIABLE SPICY_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)
set(CMAKE_PROJECT_VERSION ${SPICY_VERSION})

## Print build summary
string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)

string(STRIP "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}" cflags)
string(STRIP "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}" cxxflags)

# Global test target
add_custom_target(check COMMAND ctest --output-on-failure -C $<CONFIG> DEPENDS tests)
add_custom_target(tests DEPENDS hilti-tests spicy-tests)

# Packaging.
# Check tags the HEAD commit corresponds to.
execute_process(COMMAND git tag --points-at
    OUTPUT_VARIABLE GIT_TAGS)

if ( "${GIT_TAGS}" STREQUAL "" )
    # If the HEAD commit does not correspond to a tag it is not a release. Hide
    # the version number in packaging artifacts so we can e.g., provide stable
    # links to the latest version.
    set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-dev")
else ()
    # If the HEAD commit corresponds to a tag it is a release and we expect a
    # version number in packaging artifacts.
    set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION}")
endif ()

set(CPACK_PACKAGE_CONTACT "info@zeek.org")

set(CPACK_BINARY_DEB OFF)
set(CPACK_BINARY_RPM OFF)
set(CPACK_BINARY_STGZ OFF)
set(CPACK_BINARY_TZ OFF)
set(CPACK_BINARY_TGZ ON)

find_program(RPMBUILD rpmbuild)
if (RPMBUILD)
    set(CPACK_BINARY_RPM ON)
endif ()

find_program(DPKG_DEB dpkg-deb)
if (DPKG_DEB)
    set(CPACK_BINARY_DEB ON)
endif ()

# While this should be sufficient to set a prefix for installation, we still
# bake in other absolute paths by using `CMAKE_INSTALL_FULL_*`-style variables,
# e.g., when baking details about the installation into binaries.
set(CPACK_SET_DESTDIR ON)
set(CPACK_INSTALL_PREFIX "/opt/spicy")
set(CPACK_PACKAGE_RELOCATABLE OFF)

include(CPack)

# Emit configuration summary.

message(
    "\n====================|  Spicy Build Summary  |===================="
    "\n"
    "\nVersion:               ${CMAKE_PROJECT_VERSION}"
    "\n"
    "\nBuild type:            ${CMAKE_BUILD_TYPE}"
    "\nBuild directory:       ${PROJECT_BINARY_DIR}"
    "\nInstall prefix:        ${CMAKE_INSTALL_PREFIX}"
    "\nBuild shared libs:     ${BUILD_SHARED_LIBS}"
    "\n"
    "\nHost system:           ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION} (${CMAKE_SYSTEM_PROCESSOR})"
    "\nC compiler:            ${CMAKE_C_COMPILER} (${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION})"
    "\nC++ compiler:          ${CMAKE_CXX_COMPILER} (${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION})"
    "\n"
    "\nBuilding toolchain:    ${HAVE_TOOLCHAIN}"
    "\nBuilding Zeek support: ${HAVE_ZEEK_PLUGIN}"
    "\nBuilding fuzzers:      ${USE_FUZZING}"
    "\n"
    "\nUse ccache:            ${USE_CCACHE}"
    "\nUse gold linker:       ${GOLD_FOUND}"
    "\nUse sanitizers:        ${HILTI_HAVE_SANITIZER}"
    "\nUse backtrace:         ${HILTI_HAVE_BACKTRACE}"
    "\n"
    "\nWarnings are errors:   ${USE_WERROR}"
    "\nPrecompile headers:    ${HILTI_DEV_PRECOMPILE_HEADERS}"
    "\n"
    "\nBison version:         ${BISON_VERSION}"
    "\nCMake version:         ${CMAKE_VERSION}"
    "\nFlex version:          ${FLEX_VERSION}"
    "\nPython version:        ${Python3_VERSION}"
    "\nzlib version:          ${ZLIB_VERSION_STRING}"
    "\n"
    "\n================================================================\n"
)
