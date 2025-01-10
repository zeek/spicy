# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ DESTINATION ${CMAKE_INSTALL_DATADIR}/hilti
        PATTERN "CMakeLists.txt" EXCLUDE)
