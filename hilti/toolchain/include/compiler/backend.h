// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include "ast/declarations/module.h"
#include "base/result.h"

namespace hilti {

class Backend {
public:
    virtual ~Backend() = default;
    // TODO: This should not return a cxx unit, but it's tied to Unit.h - maybe
    // replace that file with these backends
    virtual Result<std::shared_ptr<detail::cxx::Unit>> compile(declaration::Module* mod, const std::shared_ptr<Context>& ctx) = 0;
};
} // namespace hilti
