# Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

set(SOURCES
    driver.cc
    glue-compiler.cc
    )

add_library(zeek-compiler OBJECT ${SOURCES})
target_include_directories(zeek-compiler PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..")
target_compile_options(zeek-compiler PRIVATE "-fPIC")
target_link_libraries(zeek-compiler PRIVATE spicy)
