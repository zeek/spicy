extern "C" {
int foo() { return 42; }
}

const char* __hlto_library_version __attribute__((weak)) = R"({
    "magic": "v1",
    "hilti_version": 400,
    "created": 0,
    "debug": false,
    "optimize": false
})";
