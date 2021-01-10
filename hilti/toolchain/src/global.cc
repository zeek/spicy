// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <string>
#include <utility>

#include <hilti/ast/ctors/enum.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/global.h>

using namespace hilti;

void hilti::render(std::ostream& out, const Node& node, bool include_scopes) {
    detail::renderNode(node, out, include_scopes);
}

void hilti::render(logging::DebugStream stream, const Node& node, bool include_scopes) {
    detail::renderNode(node, std::move(stream), include_scopes);
}

#ifdef HILTI_HAVE_SANITIZER
// TODO(robin): Doesn't work on Linux to have this in shared library. The weak symbol in static ASAN runtime
// wins during linking.
extern "C" {
const char* __asan_default_options() { return "detect_odr_violation=0:detect_leaks=1"; }
}
#endif
