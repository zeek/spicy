// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/node.h>
#include <hilti/compiler/unit.h>

using namespace hilti;

node::Properties declaration::ImportedModule::properties() const {
    return node::Properties{{"module", (_unit.lock() ? _unit.lock()->module().renderedRid() : std::string("-"))},
                            {"parse_extension", _parse_extension.native()},
                            {"path", _path.native()},
                            {"scope", (_scope ? _scope->str() : std::string("-"))}};
}
