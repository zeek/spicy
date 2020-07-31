# Find Zeek installation.
#
# Variables used by this module that can be set before calling find_package:
#
#  ZEEK_ROOT_DIR Set this variable to the root installation of Zeek if the
#                module has problems finding the proper installation path.
#
# Variables defined by this module:
#
#  ZEEK_FOUND        Zeek is installed.
#  ZEEK_CONFIG       Path to Zeek configuration.
#  ZEEK_CXX_FLAGS    C++ flags to compile a Zeek plugin.
#  ZEEK_CMAKE_DIR    Path to Zeek's CMake files.
#  ZEEK_INCLUDE_DIR  Path to Zeek's headers.
#  ZEEK_PLUGIN_DIR   Path to Zeek's plugin directory.
#  ZEEK_PREFIX       Path to Zeek's installation prefix.
#  ZEEK_VERSION      Version string of Zeek.
#  ZEEK_VERSION_NUMBER Numerical version of Zeek.
#  ZEEK_DEBUG_BUILD  True if Zeek was build in debug mode
#  ZEEK_EXE          Path to zeek executale
#  BifCl_EXE         Path to bifcl
#
# Interface target to link to a Zeek plugin:
#
#  Zeek::Zeek

set(zeek_mininum_version "3.0.0")

find_program(ZEEK_CONFIG zeek-config
             HINTS ${ZEEK_ROOT_DIR}/bin /usr/local/zeek/bin)

if ( ZEEK_CONFIG )
    message(STATUS "Found zeek-config at ${ZEEK_CONFIG}")
    execute_process(COMMAND "${ZEEK_CONFIG}" --include_dir
                    OUTPUT_VARIABLE ZEEK_INCLUDE_DIRS
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

    string(REPLACE ":" ";" ZEEK_CXX_FLAGS "${ZEEK_INCLUDE_DIRS}")
    list(TRANSFORM "${ZEEK_CXX_FLAGS}" PREPEND "-I" OUTPUT_VARIABLE ZEEK_CXX_FLAGS)
    string(REPLACE ";" " " ZEEK_CXX_FLAGS "${ZEEK_CXX_FLAGS}")

    execute_process(COMMAND "${ZEEK_CONFIG}" --cmake_dir
                    OUTPUT_VARIABLE ZEEK_CMAKE_DIR
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

    execute_process(COMMAND "${ZEEK_CONFIG}" --prefix
                    OUTPUT_VARIABLE ZEEK_PREFIX
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

    execute_process(COMMAND "${ZEEK_CONFIG}" --plugin_dir
                    OUTPUT_VARIABLE ZEEK_PLUGIN_DIR
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

    execute_process(COMMAND "${ZEEK_CONFIG}" --version
                    OUTPUT_VARIABLE ZEEK_VERSION
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

    execute_process(COMMAND "${ZEEK_CONFIG}" --build_type
                    OUTPUT_VARIABLE ZEEK_DEBUG_BUILD
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

    if ( "${ZEEK_DEBUG_BUILD}" STREQUAL "debug" )
        set(ZEEK_DEBUG_BUILD yes)
    else ()
        set(ZEEK_DEBUG_BUILD no)
    endif ()

    # Copied from Zeek to generate numeric version number.
    string(REGEX REPLACE "[.-]" " " version_numbers ${ZEEK_VERSION})
    separate_arguments(version_numbers)
    list(GET version_numbers 0 VERSION_MAJOR)
    list(GET version_numbers 1 VERSION_MINOR)
    list(GET version_numbers 2 VERSION_PATCH)
    set(VERSION_MAJ_MIN "${VERSION_MAJOR}.${VERSION_MINOR}")
    math(EXPR ZEEK_VERSION_NUMBER
     "${VERSION_MAJOR} * 10000 + ${VERSION_MINOR} * 100 + ${VERSION_PATCH}")

    find_program(BifCl_EXE bifcl HINTS ${ZEEK_PREFIX}/bin NO_DEFAULT_PATH)
    find_program(ZEEK_EXE zeek HINTS ${ZEEK_PREFIX}/bin NO_DEFAULT_PATH)
else ()
    set(ZEEK_VERSION "not found")
    set(ZEEK_PREFIX "not found")
    set(ZEEK_EXE "not found")
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Zeek DEFAULT_MSG ZEEK_CONFIG)

require_version("Zeek" ZEEK_FOUND ZEEK_VERSION ${zeek_mininum_version} false)

if ( ZEEK_FOUND )
    set(ZEEK_FOUND "yes" CACHE BOOL "Have Zeek's Spicy plugin" FORCE)
else ()
    set(ZEEK_FOUND "no" CACHE BOOL "Have Zeek's Spicy plugin" FORCE)
endif ()
