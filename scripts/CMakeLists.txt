# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

install(PROGRAMS precompile-headers.sh RENAME spicy-precompile-headers TYPE BIN)

find_package(Clang)

if (Clang_FOUND)
    message(
        STATUS
            "Found Clang ${Clang_VERSION} in ${CLANG_INSTALL_PREFIX}; building AST autogen tooling")

    list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
    include(AddLLVM)

    add_llvm_executable(autogen-builder-api autogen-builder-api.cc)
    target_link_libraries(autogen-builder-api PRIVATE clangTooling)
    target_include_directories(autogen-builder-api PRIVATE ${LLVM_INCLUDE_DIRS})
    target_include_directories(autogen-builder-api PRIVATE ${CLANG_INCLUDE_DIRS})
    target_compile_definitions(autogen-builder-api PRIVATE ${LLVM_DEFINITIONS})
    target_compile_definitions(autogen-builder-api PRIVATE ${CLANG_DEFINITIONS})

    add_llvm_executable(find-broken-casts find-broken-casts.cc)
    target_link_libraries(find-broken-casts PRIVATE clangTooling)
    target_include_directories(find-broken-casts PRIVATE ${LLVM_INCLUDE_DIRS})
    target_include_directories(find-broken-casts PRIVATE ${CLANG_INCLUDE_DIRS})
    target_compile_definitions(find-broken-casts PRIVATE ${LLVM_DEFINITIONS})
    target_compile_definitions(find-broken-casts PRIVATE ${CLANG_DEFINITIONS})

else ()
    message(STATUS "Could not find Clang, not building AST autogen tooling")
endif ()
