# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

# TODO: Clean this up. Turn into functions with named parameters.

### Autogenerate *.decl file for a set of operator definitions.
macro (autogen_operators outputs ns srcdir dst_decls dst_impls)
    set(_output_decls "${dst_decls}")
    set(_output_impls "${dst_impls}")

    file(GLOB _headers ${CMAKE_CURRENT_SOURCE_DIR}/${srcdir}/*.h)

    add_custom_command(
        OUTPUT ${_output_decls}
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/autogen-operators-nodes-decl ${ns}
                ${CMAKE_CURRENT_SOURCE_DIR}/${srcdir} >${_output_decls}
        DEPENDS ${PROJECT_SOURCE_DIR}/scripts/autogen-operators-nodes-decl ${_headers}
        COMMENT "Generating ${_output_decls}")

    set_source_files_properties(${_output_decls} PROPERTIES GENERATED TRUE)

    ##

    add_custom_command(
        OUTPUT "${AUTOGEN_CC}/operators-implementations.cc"
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/autogen-operators-implementations ${ns}
                ${CMAKE_CURRENT_SOURCE_DIR}/${srcdir} >${_output_impls}
        DEPENDS ${PROJECT_SOURCE_DIR}/scripts/autogen-operators-implementations ${_headers}
        COMMENT "Generating ${AUTOGEN_CC}/operators-implementations.cc")

    set_source_files_properties(${_output_impls} PROPERTIES GENERATED TRUE)
    list(APPEND ${outputs} ${_output_impls})
endmacro ()
