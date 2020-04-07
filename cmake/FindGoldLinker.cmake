
## Enable Gold linker if available.

set(GOLD_FOULD "no")

if ( USE_GOLD )
    if ( UNIX AND NOT APPLE AND NOT LLD_PATH )
        execute_process(COMMAND ${CMAKE_CXX_COMPILER} -fuse-ld=gold -Wl,--version ERROR_QUIET OUTPUT_VARIABLE ld_version)
        if ("${ld_version}" MATCHES "GNU gold")
            message(STATUS "Using Gold linker")
            set(GOLD_FOUND "yes")
            set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=gold")
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fuse-ld=gold")
        else ()
            message(STATUS "Gold linker not available")
        endif ()
    endif ()
else ()
    message(STATUS "Gold linker usage disabled")
endif ()

set(GOLD_FOUND ${GOLD_FOUND} CACHE BOOL "TRUE if we activated the Linux Gold linker")
