// @TEST-EXEC-FAIL: HILTI_JIT_SHOW_CXX_OUTPUT=1 hiltic -j %INPUT 2>output
// @TEST-EXEC: grep -q "Broken" hilti-jit-error.log
// @TEST-EXEC: grep -q "Broken" output
//
// Check that compiling broken C++ code doesn't produce any leaks or other
// unexpected output. Because the actual output depends on the underlying
// compiler, we just check for a keyword being in there.

Broken C;++.
