// With spicy-build, the library versions will match the command line arguments (-d vs not-d).
//
// @TEST-GROUP: no-jit
// @TEST-EXEC: echo == spicy-build >>output.tmp
// @TEST-EXEC: ${SPICY_BUILD} -S %INPUT && ./a.out >>output.tmp
// @TEST-EXEC: echo == spicy-build -d >>output.tmp
// @TEST-EXEC: ${SPICY_BUILD} -S -d %INPUT && ./a.out >>output.tmp
// @TEST-EXEC: cat output.tmp | sed 's/ [0-9]\{1,\}\.[0-9]\{1,\}[^[]*/ X.X.X /g' >output
// @TEST-EXEC: btest-diff output
//
// With JIT in hiltic, the library versions will match the distribution's
// build type (i.e., not the cmd line arguments).
// @TEST-EXEC: ${SPICYC} -j %INPUT | awk 'NR==1' | grep -q `${HILTI_CONFIG} --build`
// @TEST-EXEC: ${SPICYC} -j -d %INPUT | awk 'NR==2' |grep -q `${HILTI_CONFIG} --build`

#include <hilti/rt/libhilti.h>
#include <spicy/rt/libspicy.h>
#include <hilti/rt/util.h>

// Just dummy data.
const char HILTI_EXPORT HILTI_WEAK * HILTI_INTERNAL_GLOBAL(hlto_library_version) = R"({"created":1597144800.98031,"debug":false,"hilti_version":400,"magic":"v1","optimize":false})";

extern "C" int HILTI_EXPORT hilti_main() { // Point of entry for JIT
    std::cout << hilti::rt::version() << '\n';
    std::cout << spicy::rt::version() << '\n';
    return 0;
}

int main(int argc, char** argv) {
    hilti::rt::init();
    hilti_main();
    hilti::rt::done();
    return 0;
}
