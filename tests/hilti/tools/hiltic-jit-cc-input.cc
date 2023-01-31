// @TEST-DOC: Validates that object files for C++ inputs are not generated next to source.
//
// Initially we expect four files (stdout, stderr, log, input).
// @TEST-EXEC: test $(find . -type f | wc -l) -eq 4
//
// JIT the C++ file and keep the output file. It should end in the temp dir.
// @TEST-EXEC: hiltic -jT %INPUT
//
// We still expect four files (stdout, stderr, log, input).
// @TEST-EXEC: test $(find . -type f | wc -l) -eq 4

void f() {}
