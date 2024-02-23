// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/compiler/unit.h>

namespace hilti {

struct Optimizer {
public:
    Optimizer(const std::vector<std::shared_ptr<Unit>>& units) : _units(units) {}
    Optimizer(const Optimizer&) = default;
    Optimizer(Optimizer&&) = default;
    Optimizer& operator=(const Optimizer&) = delete;
    Optimizer& operator=(Optimizer&&) = delete;
    ~Optimizer() = default;

    void run();

private:
    const std::vector<std::shared_ptr<Unit>>& _units;
};

} // namespace hilti
