# Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

# Prepare environment for Zeek's BroPlugin
set(BRO_PLUGIN_BASE "${CMAKE_CURRENT_SOURCE_DIR}")
set(BRO_CONFIG_CMAKE_DIR "${ZEEK_CMAKE_DIR}")
set(BRO_CONFIG_PLUGIN_DIR "${ZEEK_PLUGIN_DIR}")
set(BRO_CONFIG_PREFIX "${ZEEK_PREFIX}")
set(BRO_CONFIG_INCLUDE_DIR "${ZEEK_INCLUDE_DIR}")
set(BROKER_ROOT_DIR "${ZEEK_PREFIX}")
set(BinPAC_ROOT_DIR "${ZEEK_PREFIX}")
set(CAF_ROOT_DIR "${ZEEK_PREFIX}")
set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${ZEEK_CMAKE_DIR}")

# We install the plugin into the Spicy installation.
set(PLUGIN_INSTALL_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/spicy/Zeek_Spicy")

set(save_c_flags ${CMAKE_C_FLAGS})
set(save_cxx_flags ${CMAKE_CXX_FLAGS})
include(BroPlugin)
set(CMAKE_C_FLAGS ${save_c_flags})
set(CMAKE_CXX_FLAGS ${save_cxx_flags})

zeek_plugin_begin(Zeek Spicy)

zeek_plugin_cc(src/file-analyzer.cc)
zeek_plugin_cc(src/plugin.cc)
zeek_plugin_cc(src/protocol-analyzer.cc)
zeek_plugin_cc(src/runtime-support.cc)
zeek_plugin_cc(src/zeek-reporter.cc)

if ( ZEEK_HAVE_JIT )
zeek_plugin_cc(src/plugin-jit.cc)
endif ()

zeek_plugin_bif(src/consts.bif)
zeek_plugin_bif(src/events.bif)
zeek_plugin_bif(src/functions.bif)

zeek_plugin_dist_files(spicy/zeek.spicy)
zeek_plugin_dist_files(spicy/zeek_rt.hlt)

# We disable Zeek's standard installation logic so that we control
# things better (like RPATHs etc.). Unfortunately Zeek doesn't just
# have a "no install, please" switch, so we change its destination
# to some scratch space.
set(BRO_PLUGIN_BRO_PLUGIN_INSTALL_PATH "${CMAKE_CURRENT_BINARY_DIR}/zeek-install-scratch")

zeek_plugin_end()

if ( ZEEK_DEBUG_BUILD )
    set(ZEEK_DEBUG_BUILD_CXX "true") # Prettify output
else ()
    set(ZEEK_DEBUG_BUILD_CXX "false")
endif ()

target_include_directories(${_plugin_lib} PRIVATE include)

# Without JIT support, we won't have the "compiler/" include directory available
# through the "zeek-compiler" target, so add it no matter what.
target_include_directories(${_plugin_lib} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)

# For JIT support.
target_link_libraries(${_plugin_lib} $<$<BOOL:${ZEEK_HAVE_JIT}>:zeek-compiler>)
target_link_libraries(${_plugin_lib} $<$<BOOL:${ZEEK_HAVE_JIT}>:spicy>)

target_link_libraries(${_plugin_lib} $<IF:$<CONFIG:Debug>,hilti-rt-debug-objects,hilti-rt-objects>)
target_link_libraries(${_plugin_lib} $<IF:$<CONFIG:Debug>,spicy-rt-debug-objects,spicy-rt-objects>)
target_link_libraries(${_plugin_lib} std::filesystem ${CMAKE_DL_LIBS})

# Create an alias for the plugin target.
add_custom_target(zeek-plugin DEPENDS ${_plugin_lib})

set(AUTOGEN_H  "${CMAKE_CURRENT_BINARY_DIR}/zeek-spicy/autogen")
file(MAKE_DIRECTORY ${AUTOGEN_H})
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in ${AUTOGEN_H}/config.h)

add_custom_command(TARGET ${_plugin_lib}
                   POST_BUILD COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_CURRENT_SOURCE_DIR}/spicy ${CMAKE_CURRENT_BINARY_DIR}/spicy)

install(FILES     ${CMAKE_CURRENT_BINARY_DIR}/__bro_plugin__
                  DESTINATION "${PLUGIN_INSTALL_DIR}")

install(DIRECTORY scripts
                  spicy
                  DESTINATION "${PLUGIN_INSTALL_DIR}")

install(TARGETS ${_plugin_lib} DESTINATION "${PLUGIN_INSTALL_DIR}/lib")

make_install_rpath(rpath_build ${BRO_PLUGIN_LIB} ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set_target_properties(${_plugin_lib} PROPERTIES BUILD_RPATH "${rpath_build}")

make_install_rpath(rpath_install ${PLUGIN_INSTALL_DIR}/lib ${CMAKE_INSTALL_FULL_LIBDIR})
set_target_properties(${_plugin_lib} PROPERTIES INSTALL_RPATH "${rpath_install}")

install_headers(include zeek-spicy runtime-support.h cookie.h)
install_headers(${CMAKE_CURRENT_BINARY_DIR}/zeek-spicy/autogen zeek-spicy/autogen config.h)

# This may need additional permissions, but we just leave it fail in that case.
install_symlink("${PLUGIN_INSTALL_DIR}" "${ZEEK_PLUGIN_DIR}/Zeek_Spicy")
