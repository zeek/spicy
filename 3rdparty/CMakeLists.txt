# Note that most of the subdirectories here don't need to be known
# to CMake because we directly pick out the pieces where we need
# them.

option(DOCTEST_NO_INSTALL  "Skip the installation process" ON)
add_subdirectory(doctest)
add_subdirectory(justrx)
add_subdirectory(tiny-process-library)

set(FIBER_SHARED OFF)
set(FIBER_OBJECT ON)
add_subdirectory(fiber)
