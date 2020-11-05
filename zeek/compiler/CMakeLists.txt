# Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

set(SOURCES
    driver.cc
    glue-compiler.cc
    )

add_library(zeek-compiler OBJECT ${SOURCES})
target_include_directories(zeek-compiler BEFORE PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..")
target_compile_options(zeek-compiler PRIVATE "-fPIC")
target_link_libraries(zeek-compiler PRIVATE spicy)

if ( ${ZEEK_VERSION_NUMBER} GREATER_EQUAL 30300 ) # Zeek >= 3.3 (aka 4.0)
    target_compile_definitions(zeek-compiler PUBLIC "HAVE_PACKET_ANALYZERS")
endif ()

add_executable(spicyz bin/spicyz.cc)
target_compile_options(spicyz PRIVATE "-Wall")
target_link_libraries(spicyz PRIVATE zeek-compiler)
target_link_spicy(spicyz PRIVATE)
target_include_directories(spicyz BEFORE PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/../plugin)

install(TARGETS spicyz RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
