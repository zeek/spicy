// @TEST-DOC: Validates that object files for C++ inputs are not generated next to source.
//
// JIT the C++ file and keep the output file. It should end in the temp dir.
// @TEST-EXEC: hiltic -jT %INPUT
//
// No object files should be in the working directory.
// @TEST-EXEC: test -z "$(find . -name '*.o' -o -name '*.obj' 2>/dev/null)"

void f() {}
