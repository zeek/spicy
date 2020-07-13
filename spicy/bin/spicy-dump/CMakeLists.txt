
add_executable(spicy-dump main.cc printer-text.cc printer-json.cc)
target_compile_options(spicy-dump PRIVATE "-Wall")
target_link_spicy(spicy-dump PRIVATE)

install(TARGETS spicy-dump RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
