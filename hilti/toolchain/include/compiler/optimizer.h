// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>
#include <vector>

#include <hilti/rt/types/shared_ptr.h>

#include <hilti/ast/id.h>
#include <hilti/compiler/unit.h>

namespace hilti {

struct Optimizer {
public:
    Optimizer(const std::vector<hilti::rt::SharedPtr<Unit>>& units) : _units(units) {}
    ~Optimizer() {}

    void run();

private:
    const std::vector<hilti::rt::SharedPtr<Unit>>& _units;
};

} // namespace hilti
