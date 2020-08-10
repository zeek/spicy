add_subdirectory(doctest)

# The JSON tests generate warnings with GCC
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
add_subdirectory(json)

add_subdirectory(justrx)
