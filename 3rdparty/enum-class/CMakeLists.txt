cmake_minimum_required(VERSION 2.8)

project(EnumClass)

add_executable(enumclass main.cpp)
target_compile_features(enumclass
	PRIVATE
		cxx_auto_type
		cxx_relaxed_constexpr
		cxx_static_assert
		cxx_strong_enums
		cxx_uniform_initialization
)
