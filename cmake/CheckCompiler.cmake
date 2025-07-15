# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

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

# Checks whether the set C++ compiler sufficiently supports C++20.
macro (cxx20_compile_test)
    check_cxx_source_compiles(
        "
        #include <optional>
        #include <span>

        int main() {
            std::optional<int> a;

            constexpr int b[]{0, 1, 2, 3, 4, 5, 6, 7, 8};
            auto s = std::span(b);
            auto s_ = s.subspan(0, 3);
        }
        "
        cxx20_works)

    if (NOT cxx20_works)
        message(FATAL_ERROR "failed using C++20 for compilation")
    endif ()
endmacro ()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${gcc_minimum_version})
        message(
            FATAL_ERROR
                "GCC version must be at least "
                "${gcc_minimum_version} for C++20 support, detected: "
                "${CMAKE_CXX_COMPILER_VERSION}")
    endif ()

elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${clang_minimum_version})
        message(
            FATAL_ERROR
                "Clang version must be at least "
                "${clang_minimum_version} for C++20 support, detected: "
                "${CMAKE_CXX_COMPILER_VERSION}")
    endif ()
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5)
        set(cxx20_flag "-std=c++20")
    endif ()
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${apple_clang_minimum_version})
        message(
            FATAL_ERROR
                "Apple Clang version must be at least "
                "${apple_clang_minimum_version} for C++20 support, detected: "
                "${CMAKE_CXX_COMPILER_VERSION}")
    endif ()
else ()
    # Unrecognized compiler: fine to be permissive of other compilers as long
    # as they are able to support C++20 and can compile the test program, but
    # we just won't be able to give specific advice on what compiler version a
    # user needs in the case it actually doesn't support C++20.
endif ()

cxx20_compile_test()
