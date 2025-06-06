# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

add_subdirectory(lib)
add_subdirectory(runtime)

add_custom_target(hilti-tests COMMENT "Building unit tests for HILTI"
                  DEPENDS hilti-rt-tests hilti-rt-configuration-tests hilti-rt-benchmark)
if (HAVE_TOOLCHAIN)
    add_subdirectory(toolchain)
    add_dependencies(hilti-tests hilti-toolchain-tests)
endif ()
