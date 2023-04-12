// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/base/util.h>

namespace spicy {

/** Enum specifying the direction of a unit field's processing. */
enum class Engine {
    Parser,   /**< field is being parsed */
    Composer, /**< field is being composed */
    All       /**< field is being parsed and composed */
};

namespace detail {
constexpr hilti::util::enum_::Value<Engine> engines[] = {
    {Engine::Parser, "parser"},
    {Engine::Composer, "composer"},
    {Engine::All, "parser/composer"},
};
} // namespace detail

constexpr auto to_string(Engine f) { return hilti::util::enum_::to_string(f, detail::engines); }

namespace engine {
constexpr auto from_string(const std::string_view& s) {
    return hilti::util::enum_::from_string<Engine>(s, detail::engines);
}
} // namespace engine

} // namespace spicy
