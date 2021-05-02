// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/compiler/unit.h>

namespace hilti {

struct Optimizer {
public:
    Optimizer(const std::vector<std::shared_ptr<Unit>>& units, const std::shared_ptr<Context> ctx)
        : _units(units), _ctx(std::move(ctx)) {}
    ~Optimizer() {}

    void run();

    auto context() const { return _ctx.lock(); }

private:
    const std::vector<std::shared_ptr<Unit>>& _units;
    std::weak_ptr<Context> _ctx;
};

} // namespace hilti
