// @TEST-REQUIRES: have-sanitizer
// @TEST-EXEC-FAIL: ${HILTIC} -j %INPUT >output 2>&1
// @TEST-EXEC: grep -q 'detected memory leaks' output
//
// If we have compiled with address/leak sanitizer, make sure it's active.

extern "C" {

#include <stdio.h>

int HILTI_EXPORT hilti_main() {
    printf("in hilti_main\n");
    auto leak = new int;
    printf("%p\n", leak);
    return 0;
}

}
