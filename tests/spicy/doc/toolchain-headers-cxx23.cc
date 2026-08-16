// @TEST-REQUIRES: ! is-windows
// @TEST-REQUIRES: have-cxx23
// @TEST-REQUIRES: using-build-directory
// @TEST-EXEC: "$(spicy-config --cxx)" $(spicy-config --cxxflags) $(printf -- '-I%s ' $(spicy-config --include-dirs-toolchain)) -std=c++23 -fsyntax-only %INPUT

#include <hilti/compiler/printer.h>
#include <spicy.h>

int main() {}
