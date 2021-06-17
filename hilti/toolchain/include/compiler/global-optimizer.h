// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <bitset>
#include <map>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/compiler/unit.h>

namespace hilti {

struct GlobalOptimizer {
public:
    using ModuleID = ID;
    using StructID = ID;
    using FieldID = ID;

    struct Uses {
        bool hook = false;
        bool declared = false;
        bool defined = false;
        bool referenced = false;
    };

    using Functions = std::map<std::tuple<ModuleID, StructID, FieldID>, Uses>;

    GlobalOptimizer(std::vector<Unit>* units, const std::shared_ptr<Context> ctx)
        : _units(units), _ctx(std::move(ctx)) {}
    ~GlobalOptimizer() { _units = nullptr; }

    void run();

private:
    std::vector<Unit>* _units = nullptr;
    std::shared_ptr<Context> _ctx;
    // Storage for field declaration and their uses.
    Functions _hooks;
};

} // namespace hilti
