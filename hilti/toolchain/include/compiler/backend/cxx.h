// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include "ast/declarations/module.h"
#include "base/result.h"
#include "compiler/backend.h"

namespace hilti {
class CxxBackend : public Backend {
public:
    Result<std::shared_ptr<detail::cxx::CxxUnit>> compile(declaration::Module* mod, const std::shared_ptr<Context>& ctx) override;
};

} // namespace hilti
