// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

/**
 * A list that for large part builds on std::list, but adds a couple of things:
 *
 *     - We add safe HILTIs-side iterators become detectably invalid when the main
 *       containers gets destroyed.
 */

#pragma once

#include <functional>
#include <initializer_list>
#include <iterator>
#include <list>
#include <memory>
#include <optional>
#include <utility>

#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/iterator.h>
#include <hilti/rt/types/list_fwd.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace list {

// template<typename I, typename Function, typename O = typename std::result_of<Function>::type>
template<typename I, typename O, typename C>
hilti::rt::List<O> make(const C& input, std::function<O(I)> func) {
    hilti::rt::List<O> output;
    for ( auto&& i : input )
        output.emplace_back(func(i));

    return output;
}

template<typename I, typename O, typename C>
hilti::rt::List<O> make(const C& input, std::function<O(I)> func, std::function<bool(I)> pred) {
    hilti::rt::List<O> output;
    for ( auto&& i : input )
        if ( pred(i) )
            output.emplace_back(func(i));

    return output;
}

/** Place-holder type for an empty list that doesn't have a known element type. */
using Empty = vector::Empty;

using vector::operator==;
using vector::operator!=;

} // namespace list

} // namespace hilti::rt
