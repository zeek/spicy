# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

add_executable(spicy-dump main.cc printer-text.cc printer-json.cc)
target_compile_options(spicy-dump PRIVATE "-Wall")
spicy_link_executable_in_tree(spicy-dump PRIVATE)

install(TARGETS spicy-dump RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
