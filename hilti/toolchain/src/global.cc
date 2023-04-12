// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <string>
#include <utility>

#include <hilti/rt/autogen/config.h>

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

#ifdef HILTI_HAVE_ASAN
// This following injects ASAN options. Note that this works on macOS, but
// *not* work on Linux because there the ASAN runtime's weak version of the
// same symbol seems to be winning during linking. However, the only option we
// set here is "detect_leaks", which on Linux is already on by default (but not
// on macOS).
extern "C" {
const char* __asan_default_options() { return "detect_leaks=1"; }
}
#endif
