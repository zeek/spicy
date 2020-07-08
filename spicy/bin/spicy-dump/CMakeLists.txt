
add_executable(spicy-dump main.cc printer-text.cc printer-json.cc)
target_compile_options(spicy-dump PRIVATE "-Wall")
target_link_libraries(spicy-dump PRIVATE spicy)

install(TARGETS spicy-dump RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
