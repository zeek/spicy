# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

# TODO: Clean this up. Turn into functions with named parameters.

### Generate the type-erased classes.
###
### If "is_constant" is true, the generated code assumes that instances can't be modified
### once created and will not deep-copy them on assignment.
macro (autogen_type_erased outputs api is_constant)
    get_filename_component(_output ${api} NAME_WE)
    set(_output "${AUTOGEN_H}/__${_output}.h")

    if (${is_constant})
        set(_const_arg "--constant")
    else ()
        set(_const_arg "")
    endif ()

    add_custom_command(
        OUTPUT ${_output}
        COMMENT "Generating ${_output}"
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/autogen-type-erased ${_const_arg} --output ${_output}
                ${CMAKE_CURRENT_SOURCE_DIR}/${api}
        DEPENDS ${PROJECT_SOURCE_DIR}/scripts/autogen-type-erased
                ${CMAKE_CURRENT_SOURCE_DIR}/${api})

    set_source_files_properties(${_output} PROPERTIES GENERATED TRUE)
    list(APPEND ${outputs} ${_output})
endmacro ()

### Merge nodes.decl files into dispatcher code.
macro (autogen_dispatchers outputs dst all_hdr)
    set(_output "${dst}")
    add_custom_command(
        OUTPUT ${_output}
        COMMENT "Generating ${_output}"
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/autogen-dispatchers --header=${all_hdr}
                --output=${_output} ${ARGN}
        DEPENDS ${PROJECT_SOURCE_DIR}/scripts/autogen-dispatchers ${ARGN})

    set_source_files_properties(${_output} PROPERTIES GENERATED TRUE)
    list(APPEND ${outputs} ${_output})
endmacro ()
