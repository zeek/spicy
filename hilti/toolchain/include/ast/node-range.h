// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <set>
#include <vector>

#include <hilti/ast/forward.h>

namespace hilti::node {

/**
 * Container to store a set of node pointers. Retains insertion order of its elements.
 */
template<typename T>
using Set = NodeVector<T>;

/**
 * A constant iterator over a range of nodes (`node::Range`). Internally, this
 * wrap around a vector iterator, and is adapted from
 * https://www.artificialworlds.net/blog/2017/05/12/c-iterator-wrapperadaptor-example.
 */
template<typename T>
class RangeIterator {
    using BaseIterator = Nodes::const_iterator;

public:
    using value_type = T*;
    using difference_type = BaseIterator::difference_type;
    using pointer = BaseIterator::pointer;
    using reference = BaseIterator::reference;
    using iterator_category = BaseIterator::iterator_category;

    explicit RangeIterator(BaseIterator i) : _iter(i) {}
    RangeIterator(const RangeIterator& other) = default;
    RangeIterator(RangeIterator&& other) noexcept = default;
    RangeIterator() {}
    ~RangeIterator() = default;

    const auto& node() const { return *_iter; }

    RangeIterator& operator=(const RangeIterator& other) = default;
    RangeIterator& operator=(RangeIterator&& other) noexcept = default;
    T* operator*() const { return _value(); }
    // T operator->() const { return &value(); }
    bool operator==(const RangeIterator& other) const { return _iter == other._iter; }
    bool operator!=(const RangeIterator& other) const { return ! (*this == other); }

    auto operator++(int) {
        auto x = RangeIterator(_iter);
        ++_iter;
        return x;
    }

    auto& operator++() {
        ++_iter;
        return *this;
    }

    auto& operator+=(difference_type i) {
        _iter += i;
        return *this;
    }

    auto& operator-=(difference_type i) {
        _iter -= i;
        return *this;
    }

    difference_type operator-(const RangeIterator& other) const { return _iter - other._iter; }
    auto operator-(difference_type i) const { return RangeIterator(_iter - i); }
    auto operator+(difference_type i) const { return RangeIterator(_iter + i); }

private:
    T* _value() const {
        if ( *_iter )
            return static_cast<T*>(*_iter);
        else
            return nullptr;
    }

    BaseIterator _iter;
};

/**
 * A range of AST nodes, defined by start and end into an existing vector of
 * nodes. The range creates a view that can be iterated over, yielding a
 * reference to each node in turn.
 */
template<typename T>
class Range {
public:
    using iterator = RangeIterator<T>;
    using const_iterator = RangeIterator<T>;
    using value_type = typename iterator::value_type;

    explicit Range() {}
    Range(typename NodeVector<T>::const_iterator begin, typename NodeVector<T>::const_iterator end)
        : _begin(begin), _end(end) {}

    explicit Range(const NodeVector<T>& nodes) : Range(nodes.begin(), nodes.end()) {}

    Range(Nodes::const_iterator begin, Nodes::const_iterator end) : _begin(begin), _end(end) {}

    Range(const Range& other) = default;
    Range(Range&& other) noexcept = default;
    ~Range() = default;

    auto begin() const { return const_iterator(_begin); }
    auto end() const { return const_iterator(_end); }
    size_t size() const { return static_cast<size_t>(_end - _begin); }
    const T& front() const { return *_begin; }
    bool empty() const { return _begin == _end; }

    operator NodeVector<T>() const {
        NodeVector<T> x;
        x.reserve(size());
        for ( auto i = _begin; i != _end; i++ )
            x.push_back(*i);

        return x;
    }

    T* operator[](size_t i) const {
        assert(static_cast<typename RangeIterator<T>::difference_type>(i) < std::distance(_begin, _end));
        return *(_begin + i);
    }

    bool operator==(const Range& other) const {
        if ( this == &other )
            return true;

        if ( size() != other.size() )
            return false;

        auto x = _begin;
        auto y = other._begin;
        while ( x != _end ) {
            if ( ! (*x++ == *y++) )
                return false;
        }

        return true;
    }

    Range& operator=(const Range& other) = default;
    Range& operator=(Range&& other) noexcept = default;

private:
    RangeIterator<T> _begin;
    RangeIterator<T> _end;
};

} // namespace hilti::node
