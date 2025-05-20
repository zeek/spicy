# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

add_subdirectory(lib)
add_subdirectory(runtime)

add_custom_target(spicy-tests COMMENT "Building unit tests for Spicy")
add_dependencies(spicy-tests spicy-rt-tests)

if (HAVE_TOOLCHAIN)
    add_subdirectory(toolchain)
    add_dependencies(spicy-tests spicy-toolchain-tests spicy-rt-tests spicy-rt-parsing-benchmark)
endif ()
