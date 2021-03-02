# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

add_subdirectory(plugin)

if ( HAVE_TOOLCHAIN )
    add_subdirectory(compiler)

    option(SPICY_IN_TREE_BUILD "" yes)
    add_subdirectory(spicy-analyzers EXCLUDE_FROM_ALL)
    add_custom_target(spicy-analyzers DEPENDS spicy-analyzers/all)
endif ()
