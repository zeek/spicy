// @TEST-EXEC-FAIL: ${HILTIC} -j %INPUT
// @TEST-EXEC: grep -q "Broken" .stderr
//
// Check that compiling broken C++ code doesn't produce any leaks or other
// unexpected output. Because the actual output depends on the underlying
// compiler, we just check for a keyword being in there.

Broken C;++.
