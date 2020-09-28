# Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

add_subdirectory(plugin)

if ( HAVE_TOOLCHAIN )
    add_subdirectory(compiler)
endif ()
