# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

### Autogenerate glue code for a set of operator definitions.
macro (autogen_operators outputs ns srcdir autogen_h autogen_cc)
    set(_outputs "${autogen_h}/__ast-visitor-dispatcher.h" "${autogen_h}/__ast-forward.h"
                 "${autogen_cc}/ast-visitor-dispatcher.cc")

    file(GLOB _operators ${CMAKE_CURRENT_SOURCE_DIR}/${srcdir}/*.cc)

    add_custom_command(
        OUTPUT ${_outputs}
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/autogen-operators ${ns} ${autogen_h} ${autogen_cc} --
                ${_operators}
        DEPENDS ${PROJECT_SOURCE_DIR}/scripts/autogen-operators ${_operators}
        COMMENT "Generating operator glue code ...")

    set_source_files_properties(${outputs} PROPERTIES GENERATED TRUE)
    set(${outputs} ${_outputs})
endmacro ()
