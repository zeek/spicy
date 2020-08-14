#ifndef RETURN_VALUE
#error RETURN_VALUE is undefined. Set it to an integer value to return from the function in this library.
#endif

extern "C" {
int foo() { return RETURN_VALUE; }
}

const char* __hlto_library_version __attribute__((weak)) = R"({
    "magic": "v1",
    "hilti_version": 400,
    "created": 0,
    "debug": false,
    "optimize": false
})";
