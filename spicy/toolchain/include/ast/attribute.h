// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/attribute.h>

namespace spicy::attribute::kind {

using hilti::attribute::Kind;

// In the following, we predefine all attributes that are part of the Spicy
// language. For clarity, we do that even if there's an equivalent HILTI
// attribute already. Since attributes compare by name, any attribute defined
// here will be considered equal to a HILTI one bearing the same name.

const Kind AlwaysEmit("&always-emit");
const Kind Anonymous("&anonymous");
const Kind BitOrder("&bit-order");
const Kind ByteOrder("&byte-order");
const Kind Chunked("&chunked");
const Kind Convert("&convert");
const Kind Count("&count");
const Kind Cxxname("&cxxname");
const Kind CxxAnyAsPtr("&cxx-any-as-ptr");
const Kind Default("&default");
const Kind Eod("&eod");
const Kind IPv4("&ipv4");
const Kind IPv6("&ipv6");
const Kind MaxSize("&max-size");
const Kind Nosub("&nosub");
const Kind Optional("&optional");
const Kind Originator("&originator");
const Kind ParseAt("&parse-at");
const Kind ParseFrom("&parse-from");
const Kind Priority("&priority");
const Kind Requires("&requires");
const Kind Responder("&responder");
const Kind Size("&size");
const Kind Synchronize("&synchronize");
const Kind Transient("&transient");
const Kind Try("&try");
const Kind Type("&type");
const Kind Until("&until");
const Kind UntilIncluding("&until-including");
const Kind While("&while");

// Hooks
const Kind Debug("%debug");
const Kind Error("%error");
const Kind Foreach("%foreach");

} // namespace spicy::attribute::kind
