# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

# Settings to pass down in Zeek plugin build.
option(SPICY_HAVE_TOOLCHAIN "" "${HAVE_TOOLCHAIN}")
option(SPICY_IN_TREE_BUILD "" yes)
option(SPICY_ZEEK_INSTALL_PLUGIN "" "${SPICY_ZEEK_INSTALL_PLUGIN}")

set(HILTI_CONFIG  "${HILTI_CONFIG}" CACHE FILEPATH "")
set(SPICY_CONFIG  "${PROJECT_BINARY_DIR}/bin/spicy-config" CACHE FILEPATH "")
set(ZEEK_CONFIG   "${ZEEK_CONFIG}" CACHE FILEPATH "")
set(ZEEK_ROOT_DIR "${ZEEK_ROOT_DIR}" CACHE FILEPATH "")

add_subdirectory(spicy-plugin)
add_subdirectory(spicy-analyzers EXCLUDE_FROM_ALL)

if ( ZEEK_FOUND )
    set(HAVE_ZEEK_PLUGIN "yes" CACHE BOOL "")
else ()
    set(HAVE_ZEEK_PLUGIN "no" CACHE BOOL "")
endif ()
