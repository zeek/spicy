# Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

add_subdirectory(plugin)
add_subdirectory(compiler)

add_executable(spicyz bin/spicyz.cc)
target_compile_options(spicyz PRIVATE "-Wall")
target_link_libraries(spicyz PRIVATE zeek-compiler spicy)
target_include_directories(spicyz BEFORE PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/plugin)

install(TARGETS spicyz RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
