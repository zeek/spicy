# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

# Adapted from Zeek.

# 9.0 works
# 10.x is untested
set(clang_minimum_version "9.0")

# 11.0 comes with 10.15 (Catalina) and works
set(apple_clang_minimum_version "11.0")

# 7.x is not compiling HILTI/Spicy, although the standard library seems to be recent enough.
# 8.x is untested.
# 9.1.1 works.
set(gcc_minimum_version "8.3")

include(CheckCXXSourceCompiles)

# Checks whether the set C++ compiler sufficiently supports C++17.
macro (cxx17_compile_test)
    check_cxx_source_compiles(
        "
        #include <optional>
        int main() { std::optional<int> a; }" cxx17_works)

    if (NOT cxx17_works)
        message(FATAL_ERROR "failed using C++17 for compilation")
    endif ()
endmacro ()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${gcc_minimum_version})
        message(
            FATAL_ERROR
                "GCC version must be at least "
                "${gcc_minimum_version} for C++17 support, detected: "
                "${CMAKE_CXX_COMPILER_VERSION}")
    endif ()

elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${clang_minimum_version})
        message(
            FATAL_ERROR
                "Clang version must be at least "
                "${clang_minimum_version} for C++17 support, detected: "
                "${CMAKE_CXX_COMPILER_VERSION}")
    endif ()
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5)
        set(cxx17_flag "-std=c++1z")
    endif ()
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${apple_clang_minimum_version})
        message(
            FATAL_ERROR
                "Apple Clang version must be at least "
                "${apple_clang_minimum_version} for C++17 support, detected: "
                "${CMAKE_CXX_COMPILER_VERSION}")
    endif ()
else ()
    # Unrecognized compiler: fine to be permissive of other compilers as long
    # as they are able to support C++17 and can compile the test program, but
    # we just won't be able to give specific advice on what compiler version a
    # user needs in the case it actually doesn't support C++17.
endif ()

cxx17_compile_test()
