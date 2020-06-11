## LLVM/Clang for JIT. Also see see http://llvm.org/docs/CMake.html#embedding-llvm-in-your-project.
##
## The module considers the following variables:
##
## CLANG_ROOT                  Path to prefix of clang installation
## CMAKE_CXX_COMPILER          If that's a clang, we use it to find the pieces we need.
## LLVM_ROOT                   Path to prefix of LLVM installation
##
## The module sets the following variables
##
## CLANG_JIT_FOUND             True if we have everything necessary for JIT
## CLANG_ROOT                  Path to prefix of clang installation
## CLANG_EXECUTABLE            Path to clang++
## CLANG_GCC_INSTALLATION      Path to the GGC installation that clang is selecting
## CLANG_RESOURCE_DIR          Path to clang's resource directory (can be set to override)
## LLVM_ROOT                   Path to prefix of LLVM installation
## CLANG_VERSION               Version of clang we'll be using for JIT
## LLVM_VERSION                Version of LLVM we'll be usign for JIT

# These are the minimum version for JIT support, not for compiling the HILTI/Spicy.

# 9.0 works
# 10.x is untested
set(llvm_mininum_version "3.0.0")
set(clang_mininum_version "3.0.0")

# The GCC toolchain is important at runtime, and supports lower versions compared
# to when we use GCC to compile HILTI/Spicy itself.
#
# 7 seems to work.
# 8 is untested.
# 9 is untested.
set(gcc_toolchain_minimum_version "7")

macro(error msg)
    message(STATUS "Warning: ${msg}")
    set(CLANG_JIT_FOUND no)
endmacro()

set(CLANG_JIT_FOUND yes)

if ( NOT CLANG_ROOT AND NOT LLVM_ROOT )
    # If our standard compiler is clang, we prefer an LLVM that's at the
    # same place. So we look for llvm-config inside the same directory as
    # clang itself and ask it for its paths.
    if ( "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" )
        string(REPLACE "/clang++" "/llvm-config" LLVM_CONFIG "${CMAKE_CXX_COMPILER}")
        if ( EXISTS "${LLVM_CONFIG}" )
          execute_process(COMMAND ${LLVM_CONFIG} --prefix OUTPUT_VARIABLE LLVM_ROOT OUTPUT_STRIP_TRAILING_WHITESPACE)
        endif ()
    endif ()
endif ()

if ( LLVM_ROOT AND NOT CLANG_ROOT )
    set(CLANG_ROOT ${LLVM_ROOT})
endif ()

if ( CLANG_ROOT AND NOT LLVM_ROOT )
    set(LLVM_ROOT ${CLANG_ROOT})
endif ()

# Inspired by https://lowlevelbits.org/building-an-llvm-based-tool.-lessons-learned/

if ( "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" )
    # Also try the prefix where clang++ is installed (which can be different from
    # what llvm-config tells us.)
    get_filename_component(_cxx_compiler_prefix "${CMAKE_CXX_COMPILER}/" DIRECTORY)
    get_filename_component(_cxx_compiler_prefix "${_cxx_compiler_prefix}/" DIRECTORY)
endif ()

set(SEARCH_PATHS
  ${LLVM_ROOT}
  ${LLVM_ROOT}/lib/cmake
  ${LLVM_ROOT}/lib/cmake/llvm
  ${LLVM_ROOT}/share/llvm/cmake/
  ${CLANG_ROOT}
  ${CLANG_ROOT}/lib/cmake
  ${CLANG_ROOT}/lib/cmake/clang
  ${CLANG_ROOT}/share/clang/cmake/
  ${_cxx_compiler_prefix}
)

set(search_default_path "")
if ( CLANG_ROOT OR LLVM_ROOT )
    set(search_default_path "NO_DEFAULT_PATH")
endif ()

find_package(LLVM CONFIG PATHS ${SEARCH_PATHS} ${search_default_path})
find_package(Clang CONFIG PATHS ${SEARCH_PATHS} ${search_default_path})

set(CLANG_JIT_FOUND yes)

if ( NOT LLVM_INSTALL_PREFIX )
    set(LLVM_ROOT "not found")
    error("Did not find LLVM installation")
endif ()

if ( CLANG_INSTALL_PREFIX )
    file(STRINGS ${CLANG_INSTALL_PREFIX}/include//clang/Basic/Version.inc CLANG_VERSION
                 REGEX " CLANG_VERSION "
                 LIMIT_COUNT 1)
    separate_arguments(CLANG_VERSION)
    list(GET CLANG_VERSION 2 CLANG_VERSION)
else ()
    set(CLANG_ROOT "not found")
    error("Did not find Clang installation")
endif ()

require_version("LLVM"  LLVM_FOUND LLVM_VERSION ${llvm_mininum_version} false)
require_version("Clang" CLANG_FOUND CLANG_VERSION ${clang_mininum_version} false)

set(CLANG_EXECUTABLE "n/a")
set(CLANG_GCC_INSTALLATION "n/a")
set(CLANG_ROOT "${CLANG_INSTALL_PREFIX}")
set(LLVM_ROOT "${LLVM_INSTALL_PREFIX}")

if ( CLANG_JIT_FOUND )
    if ( "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" )
        set(CLANG_EXECUTABLE ${CMAKE_CXX_COMPILER})
    else ()
        set(CLANG_EXECUTABLE "${CLANG_ROOT}/bin/clang++")
    endif()

    if ( EXISTS ${CLANG_EXECUTABLE} )
        execute_process(COMMAND /bin/sh "-c" "${CLANG_EXECUTABLE} -v 2>&1 | awk '/Selected GCC installation/ { print $NF; }'"
                        OUTPUT_VARIABLE CLANG_GCC_INSTALLATION
                        OUTPUT_STRIP_TRAILING_WHITESPACE)

        if ( NOT CLANG_RESOURCE_DIR )
            execute_process(COMMAND ${CLANG_EXECUTABLE} -print-resource-dir
                            OUTPUT_VARIABLE CLANG_RESOURCE_DIR
                            OUTPUT_STRIP_TRAILING_WHITESPACE)
        endif ()

        if ( CLANG_GCC_INSTALLATION )
            string(REGEX REPLACE "^.*/([0-9])$" "\\1" toolchain_version ${CLANG_GCC_INSTALLATION})
            if ( NOT toolchain_version OR ${toolchain_version} LESS ${gcc_toolchain_minimum_version} )
                message(STATUS "Warning: GCC toolchain version must be at least "
                        "${gcc_toolchain_minimum_version} for JIT support, detected: "
                        "${${toolchain_version}}")
                set(CLANG_JIT_FOUND no)
            endif ()
        else ()
            set(CLANG_GCC_INSTALLATION "n/a")
        endif ()

        if ( NOT CLANG_RESOURCE_DIR )
            set(CLANG_RESOURCE_DIR "not found")
            error("Could not determine clang's resource directory")
        endif ()

    else ()
        set(CLANG_EXECUTABLE "not found")
        set(CLANG_RESOURCE_DIR "not found")
        error("Could not determine path of clang++")
    endif ()

    if ( LLVM_LINK_LLVM_DYLIB )
        # If there's a shared LLVM lib, we use that because the clang libraries might be doing the same
        # and we'd get duplicated symbols otherwise. Note that the clang-cpp shared library always
        # exists since clang 9.
        set(llvm_libs LLVM)
        set(clang_libs clang-cpp)
    else ()
        set(llvm_libs LLVMOrcJIT LLVMX86AsmParser LLVMX86CodeGen)
        set(clang_libs clangFrontend clangCodeGen)
    endif ()

    message(STATUS "Linking against LLVM libraries '${llvm_libs}'")
    message(STATUS "Linking against clang libraries '${clang_libs}'")

    add_library(clang-jit INTERFACE)
    target_include_directories(clang-jit BEFORE INTERFACE ${LLVM_INCLUDE_DIRS})
    target_compile_definitions(clang-jit INTERFACE ${LLVM_DEFINITIONS})
    target_link_options(clang-jit INTERFACE "LINKER:-rpath;${LLVM_LIBRARY_DIR}")
    target_link_libraries(clang-jit INTERFACE ${llvm_libs} ${clang_libs})
endif ()
