### A collection of small helpers for the HILTI/Spicy build system.

# Add the likely Bison include directory to Bison sources to avoid version mismatches.
function(bison_source src output_dir)
    string(REGEX REPLACE "/bin/bison" "/include" bison_include "${BISON_EXECUTABLE}")
    set_source_files_properties(${src} PROPERTIES INCLUDE_DIRECTORIES "${bison_include};${FLEX_INCLUDE_DIR};${output_dir}")
endfunction()

# Install a set of header files from a directory location.
function(install_headers src dst)
    if ( NOT IS_ABSOLUTE "${src}" )
        set(src "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
    endif ()

    if ( NOT IS_ABSOLUTE "${dst}" )
        set(dst_msg "${CMAKE_INSTALL_FULL_INCLUDEDIR}/${dst}")
        set(dst "${CMAKE_INSTALL_INCLUDEDIR}/${dst}")
    endif ()

    if ( ARGN )
        foreach ( i ${ARGN} )
            install(FILES ${src}/${i} DESTINATION ${dst})
        endforeach ()
    else ()
        install(CODE "message(STATUS \"Installing: ${dst_msg}/*\")")

        install(DIRECTORY ${src}/
                          DESTINATION ${dst}
                          MESSAGE_NEVER
                          FILES_MATCHING PATTERN "*.h"
                                         PATTERN "*.hpp"
                                         PATTERN "*.hh"
                                         PATTERN "3rdparty*" EXCLUDE
                          )
    endif ()
endfunction ()

# Add a symlink at installation time.
function(install_symlink filepath sympath)
    install(CODE "message(\"-- Creating symbolic link: ${sympath} -> ${filepath}\")")
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${filepath} ${sympath})")
endfunction(install_symlink)

# Initialize a variable that'll go into a {hilti,spicy}/config.cc
# file. This performans some normalization: turn lists into
# space-separated strings and strip/reduce whitespace.
function(set_config_val dst val)
    if ( NOT "${val}" STREQUAL "" )
        string(REPLACE ";" " " _x "${val}")
        string(STRIP "${_x}" _x)
        string(REGEX REPLACE "  *" " " _x "${_x}")
        set(${dst} "${_x}" PARENT_SCOPE)
    else ()
        set(${dst} "" PARENT_SCOPE)
    endif ()
endfunction()

function(make_install_rpath dst relative_from relative_to)
    # The following is from "Professional CMake" to set target's RPATH relative to their location.
    if ( APPLE )
        set(base_point "@loader_path")
    else ()
        set(base_point "$ORIGIN")
    endif ()

    file(RELATIVE_PATH relative_lib_path ${relative_from} ${relative_to})
    set(${dst} "${base_point};${base_point}/${relative_lib_path}" PARENT_SCOPE)
endfunction ()

# Warn or abort if we don't a given version isn't recent enough.
function(require_version name found have need require)
    if ( NOT ${found} )
        if ( require )
            message(FATAL_ERROR "${name} required, but not found")
        else ()
            set(${found} no PARENT_SCOPE)
            set(${have} "not found")
        endif ()
    else ()
         if ( ${have} VERSION_LESS "${need}" )
            if ( require )
                message(FATAL_ERROR "Need ${name} version >= ${need}, found ${${have}}")
            endif ()

            message(STATUS "Warning: Need ${name} version >= ${need}, found ${${have}}")
            set(${found} no PARENT_SCOPE)
            set(${have} "${${have}} (error: too old, must be at least ${zeek_mininum_version})" PARENT_SCOPE)
        endif()
    endif()
endfunction ()

# Link a target against libhilti. This picks the right version of
# libhilti (shared or object) based on the build configuration.
function(target_link_hilti lib)
    if ( BUILD_SHARED_LIBS )
        target_link_libraries(${lib} "${ARGN}" hilti)
    else ()
        target_link_libraries(${lib} "${ARGN}" hilti-objects)
        target_link_libraries(${lib} "${ARGN}" $<IF:$<CONFIG:Debug>,hilti-rt-debug-objects,hilti-rt-objects>) # doesn't transfer from hilti-objects
        set_property(TARGET ${lib} PROPERTY ENABLE_EXPORTS true)
    endif ()
endfunction ()

# Link a target against libspicy. This picks the right version of
# libspicy (shared or object) based on the build configuration.
function(target_link_spicy lib)
    if ( BUILD_SHARED_LIBS )
        target_link_libraries(${lib} "${ARGN}" spicy)
    else ()
        target_link_libraries(${lib} "${ARGN}" spicy-objects)
        target_link_libraries(${lib} "${ARGN}" $<IF:$<CONFIG:Debug>,spicy-rt-debug-objects,spicy-rt-objects>) # doesn't transfer from spicy-objects
        set_property(TARGET ${lib} PROPERTY ENABLE_EXPORTS true)
    endif ()

    target_link_hilti(${lib} "${ARGN}")
endfunction ()
