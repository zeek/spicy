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
// @TEST-EXEC: ! have-jit || ${SPICYC} -j %INPUT | grep -q `${HILTI_CONFIG} --build`
// @TEST-EXEC: ! have-jit || ${SPICYC} -j -d %INPUT | grep -q `${HILTI_CONFIG} --build`


#include <hilti/rt/libhilti.h>
#include <spicy/rt/libspicy.h>

extern "C" int hilti_main() { // Point of entry for JIT
    std::cout << hilti::rt::version() << std::endl;
    std::cout << spicy::rt::version() << std::endl;
    return 0;
}

int main(int argc, char** argv) {
    hilti::rt::init();
    hilti_main();
    hilti::rt::done();
    return 0;
}
