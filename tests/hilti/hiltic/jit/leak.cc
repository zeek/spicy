// @TEST-REQUIRES: have-sanitizer
// @TEST-REQUIRES: test -z "${ASAN_OPTIONS}"
// @TEST-EXEC-FAIL: ${HILTIC} -j %INPUT >output 2>&1
// @TEST-EXEC: grep -q 'detected memory leaks' output
//
// If we have compiled with address/leak sanitizer, make sure it's active.

#include <cstdio>

#include <hilti/rt/libhilti.h>

extern "C" {

int HILTI_EXPORT hilti_main() {
    printf("in hilti_main\n");
    auto leak = new int;
    printf("%p\n", leak);
    return 0;
}

}
