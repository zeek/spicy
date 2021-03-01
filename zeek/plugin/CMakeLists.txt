# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

# Prepare environment for Zeek's BroPlugin
set(BRO_PLUGIN_BASE "${CMAKE_CURRENT_SOURCE_DIR}")
set(BRO_CONFIG_CMAKE_DIR "${ZEEK_CMAKE_DIR}")
set(BRO_CONFIG_PLUGIN_DIR "${ZEEK_PLUGIN_DIR}")
set(BRO_CONFIG_PREFIX "${ZEEK_PREFIX}")
set(BRO_CONFIG_INCLUDE_DIR "${ZEEK_INCLUDE_DIRS}")
set(BROKER_ROOT_DIR "${ZEEK_PREFIX}")
set(BinPAC_ROOT_DIR "${ZEEK_PREFIX}")
set(CAF_ROOT_DIR "${ZEEK_PREFIX}")
set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${ZEEK_CMAKE_DIR}")

# We install the plugin into the Spicy installation if requested.
OPTION(ZEEK_INSTALL_PLUGIN "Install Zeek plugin into Zeek installation" ON)
set(PLUGIN_INSTALL_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/spicy/Zeek_Spicy")

set(save_c_flags ${CMAKE_C_FLAGS})
set(save_cxx_flags ${CMAKE_CXX_FLAGS})
include(BroPlugin)
set(CMAKE_C_FLAGS ${save_c_flags})
set(CMAKE_CXX_FLAGS ${save_cxx_flags})

zeek_plugin_begin(_Zeek Spicy)

if ( HAVE_TOOLCHAIN )
    zeek_plugin_cc(src/driver.cc)
endif ()

zeek_plugin_cc(src/file-analyzer.cc)
zeek_plugin_cc(src/plugin.cc)
zeek_plugin_cc(src/packet-analyzer.cc)
zeek_plugin_cc(src/protocol-analyzer.cc)
zeek_plugin_cc(src/runtime-support.cc)
zeek_plugin_cc(src/zeek-reporter.cc)

zeek_plugin_bif(src/consts.bif)
zeek_plugin_bif(src/events.bif)
zeek_plugin_bif(src/functions.bif)

zeek_plugin_dist_files(spicy/zeek.spicy)
zeek_plugin_dist_files(spicy/zeek_rt.hlt)

if ( !ZEEK_INSTALL_PLUGIN )
    # Unfortunately Zeek doesn't just have a "no install, please" switch,
    # so we change its destination to some scratch space.
    set(BRO_PLUGIN_BRO_PLUGIN_INSTALL_PATH "${CMAKE_CURRENT_BINARY_DIR}/zeek-install-scratch")
endif ()

zeek_plugin_end()

if ( ZEEK_DEBUG_BUILD )
    set(ZEEK_DEBUG_BUILD_CXX "true") # Prettify output
else ()
    set(ZEEK_DEBUG_BUILD_CXX "false")
endif ()

target_include_directories(${_plugin_lib} BEFORE PRIVATE include)

if ( HAVE_TOOLCHAIN )
    target_link_libraries(${_plugin_lib} zeek-compiler)
    hilti_link_libraries(${_plugin_lib})
    spicy_link_libraries(${_plugin_lib})
else ()
    hilti_link_object_libraries(${_plugin_lib})
    spicy_link_object_libraries(${_plugin_lib})
endif ()


# Create an alias for the plugin target.
add_custom_target(zeek-plugin DEPENDS ${_plugin_lib})

set(AUTOGEN_H  "${CMAKE_CURRENT_BINARY_DIR}/zeek-spicy/autogen")
file(MAKE_DIRECTORY ${AUTOGEN_H})
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in ${AUTOGEN_H}/config.h)

add_custom_command(TARGET ${_plugin_lib}
                   POST_BUILD COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_CURRENT_SOURCE_DIR}/spicy ${CMAKE_CURRENT_BINARY_DIR}/spicy)
