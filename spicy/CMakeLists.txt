# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

add_subdirectory(lib)
add_subdirectory(runtime)

if ( HAVE_TOOLCHAIN )
    add_subdirectory(toolchain)
    add_custom_target(spicy-tests DEPENDS spicy-toolchain-tests spicy-rt-tests)
else ()
    add_custom_target(spicy-tests DEPENDS spicy-rt-tests)
endif ()
