# Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

if ( ZEEK_HAVE_JIT )
add_subdirectory(compiler)
endif()

add_subdirectory(plugin)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/bin/spicyz ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/spicyz COPYONLY)

# Installation
install(PROGRAMS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/spicyz DESTINATION ${CMAKE_INSTALL_BINDIR})
