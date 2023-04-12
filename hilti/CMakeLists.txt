# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

add_subdirectory(lib)
add_subdirectory(runtime)

if (HAVE_TOOLCHAIN)
    add_subdirectory(toolchain)
    add_custom_target(
        hilti-tests DEPENDS hilti-toolchain-tests hilti-rt-tests hilti-rt-configuration-tests
        COMMENT "Running hilti-tests")
else ()
    add_custom_target(hilti-tests DEPENDS hilti-rt-tests hilti-rt-configuration-tests
                      COMMENT "Running hilti-tests")
endif ()
