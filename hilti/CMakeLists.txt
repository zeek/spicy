# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

add_subdirectory(lib)
add_subdirectory(runtime)

if ( HAVE_TOOLCHAIN )
    add_subdirectory(toolchain)
    add_custom_target(hilti-tests DEPENDS hilti-toolchain-tests hilti-rt-tests hilti-rt-configuration-tests)
else ()
    add_custom_target(hilti-tests DEPENDS hilti-rt-tests hilti-rt-configuration-tests)
endif ()

option("HILTI_DEV_PRECOMPILE_HEADERS" "Precompile headers for developer tests" ON)

if (${HILTI_DEV_PRECOMPILE_HEADERS} AND TARGET hilti-config)
    # Precompile libhilti for use in JIT during development.
    #
    # We only use precompiled headers during JIT, but e.g., not to during
    # compilation of Spicy itself. This gives us the benefits of JIT without
    # e.g., making it harder for ccache to work during development. It also
    # allows us to punt on some trickier cleanups of header files.
    add_custom_command(
        OUTPUT ${PROJECT_BINARY_DIR}/cache/spicy/precompiled_libhilti.h
        COMMAND
            ${CMAKE_COMMAND} -E env SPICY_CACHE=${PROJECT_BINARY_DIR}/cache/spicy
                ${PROJECT_SOURCE_DIR}/scripts/precompile-headers.sh --hilti-config $<TARGET_FILE:hilti-config>
        DEPENDS
            ${PROJECT_SOURCE_DIR}/scripts/precompile-headers.sh
            ${CMAKE_CURRENT_SOURCE_DIR}/runtime/include/libhilti.h
            hilti-config)
    add_custom_target(precompiled-headers
        ALL
        DEPENDS ${PROJECT_BINARY_DIR}/cache/spicy/precompiled_libhilti.h)
endif ()
