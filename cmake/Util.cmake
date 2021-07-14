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
            set(${have} "${${have}} (error: too old, must be at least ${need})" PARENT_SCOPE)
        endif()
    endif()
endfunction ()

# Internal helper to link in all object libraries that libhilti needs.
function(hilti_link_object_libraries_in_tree lib)
    if ( HAVE_TOOLCHAIN )
        target_link_libraries(${lib} "${ARGN}" hilti-objects)
    endif ()

    if ( CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_link_libraries(${lib} "${ARGN}" hilti-rt-debug-objects)
    else ()
        target_link_libraries(${lib} "${ARGN}" hilti-rt-objects)
    endif ()

    set(_private "")
    if ( NOT "${ARGN}" STREQUAL "" )
        set(_private "PRIVATE")
    endif()

    target_link_libraries(${lib} ${_private} reproc++)
    target_link_libraries(${lib} ${_private} jrx-objects)
    target_link_libraries(${lib} ${_private} fiber::fiber)
endfunction()

# Link a library against libhilti. This picks the right version of
# libhilti (shared or object) based on the build configuration.
function(hilti_link_libraries_in_tree lib)
    if ( BUILD_SHARED_LIBS )
        target_link_libraries(${lib} "${ARGN}" hilti)
    else ()
        hilti_link_object_libraries_in_tree(${lib} "${ARGN}")
    endif ()
endfunction ()

# Link an executable against libhilti. This picks the right version of
# libhilti (shared or object) based on the build configuration.
function(hilti_link_executable_in_tree exec)
    # Ideally, we'd just link against the static hilti library here. However,
    # ENABLE_EXPORTS doesn't seem to apply through to that, and we'd get
    # missing symbol errors at runtime. So instead we link directly
    # against our set of objects libraries by calling hilti_link_libraries_in_tree().
    hilti_link_libraries_in_tree(${exec} "${ARGN}")
    set_property(TARGET ${exec} PROPERTY ENABLE_EXPORTS true)
endfunction ()

# Internal helper to link in all object libraries that libspicy needs.
function(spicy_link_object_libraries_in_tree lib)
    if ( HAVE_TOOLCHAIN )
        target_link_libraries(${lib} "${ARGN}" spicy-objects)
    endif ()

    if ( CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_link_libraries(${lib} "${ARGN}" spicy-rt-debug-objects)
    else ()
        target_link_libraries(${lib} "${ARGN}" spicy-rt-objects)
    endif ()
endfunction()

# Link a library against libspicy. This picks the right version of
# libspicy (shared or object) based on the build configuration.
function(spicy_link_libraries_in_tree lib)
    if ( BUILD_SHARED_LIBS )
        target_link_libraries(${lib} "${ARGN}" spicy)
    else ()
        spicy_link_object_libraries_in_tree(${lib} "${ARGN}")
    endif ()
endfunction ()

# Link an executable against libspicy. This picks the right version of
# libspicy (shared or object) based on the build configuration.
function(spicy_link_executable_in_tree exec)
    # Similar comment here as hilti_link_executable_in_tree().
    hilti_link_libraries_in_tree(${exec} "${ARGN}")
    spicy_link_libraries_in_tree(${exec} "${ARGN}")
    set_property(TARGET ${exec} PROPERTY ENABLE_EXPORTS true)
endfunction ()

# Wrapper around `BISON_TARGET` with Spicy-specific preprocessing.
macro(BISON_TARGET_PP Name BisonInput BisonOutput)
    # Name of the preprocessed Bison input.
    string(JOIN "." BisonInputPP "${BisonOutput}" "pp")

    # Preprocess the input file:
    #
    # - in versions <bison-3.3.0 `api.parser.name` was called `parser_class_name`
    if (${BISON_VERSION} VERSION_LESS "3.3.0")
        add_custom_command(
            OUTPUT ${BisonInputPP}
            DEPENDS ${BisonInput}
            COMMAND sed
                -e 's/%require\ \"3.3\"/%require\ \"3.0\"/'
                -e 's/api.parser.class/parser_class_name/'
            ${BisonInput} > ${BisonInputPP}
            WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
            COMMENT "Preprocessing Bison file ${BisonInput}")
    else()
        add_custom_command(
            OUTPUT ${BisonInputPP}
            DEPENDS ${BisonInput}
            COMMAND ${CMAKE_COMMAND} -E copy_if_different ${BisonInput} ${BisonInputPP}
            WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
            COMMENT "Preprocessing Bison file ${BisonInput}")
    endif()

    # Pass preprocessed file to `BISON_TARGET`.
    #
    # TODO(bbannier): Since `ARGV` is a list of lists normal list manipulations like
    # `list(REPLACE_AT ...)` do not seem to work so we create a new output list.
    set(i 0)
    foreach(arg ${ARGV})
        if (i EQUAL 1)
            list(APPEND args "${BisonInputPP}")
        else()
            list(APPEND args "${arg}")
        endif()
        MATH(EXPR i "${i}+1")
    endforeach()

    # Invoke the actual Bison processing.
    BISON_TARGET(${args})
endmacro()
