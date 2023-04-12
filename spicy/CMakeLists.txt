# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

add_subdirectory(lib)
add_subdirectory(runtime)

if (HAVE_TOOLCHAIN)
    add_subdirectory(toolchain)
    add_custom_target(spicy-tests DEPENDS spicy-toolchain-tests spicy-rt-tests
                      COMMENT "Running spicy-tests")
else ()
    add_custom_target(spicy-tests DEPENDS spicy-rt-tests COMMENT "Running spicy-tests")
endif ()
