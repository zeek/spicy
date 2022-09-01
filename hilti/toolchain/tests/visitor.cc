// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
//
// @TEST-REQUIRES: using-build-directory
// @TEST-EXEC: test-visitor >&2
//
// Note: This is compiled through CMakeLists.txt.

#include <doctest/doctest.h>

#include <algorithm>
#include <optional>
#include <sstream>

#include <hilti/ast/detail/visitor.h>
#include <hilti/hilti.h>

static auto ast() {
    auto s = hilti::declaration::Type(hilti::ID("s"), hilti::type::String());
    auto i32 = hilti::declaration::Type(hilti::ID("i32"), hilti::type::SignedInteger(32));
    auto d = hilti::declaration::Type(hilti::ID("d"), hilti::type::Real());
    auto e = hilti::declaration::LocalVariable(hilti::ID("e"), hilti::type::void_);
    auto c = hilti::declaration::LocalVariable(hilti::ID("c"), hilti::type::Bool(),
                                               hilti::expression::Ctor(hilti::ctor::Bool(true)));

    std::vector<hilti::Declaration> x = {s, i32, d, e, c};
    auto m = hilti::Module(hilti::ID("test"), std::move(x));
    return hilti::Node{std::move(m)};
}

TEST_SUITE_BEGIN("Visitor");

TEST_CASE("Single-shot, result, constant node") {
    struct Visitor : hilti::visitor::PreOrder<void, Visitor>, hilti::type::Visitor {
        using Visitor::base_t::base_t;

        void operator()(const hilti::Module& m) { result = "(mo)"; }
        void operator()(const hilti::ID& id) { result = "(id)"; }
        void operator()(const hilti::Type& t, const_position_t i) { result = "(t)"; }
        void operator()(const hilti::type::String& s, Visitor::position_t&) override { result = "(ts)"; }
        void operator()(const hilti::type::SignedInteger& i, Visitor::position_t&) override { result = "(ti)"; }
        void operator()(const hilti::expression::Ctor& c, const_position_t i) { result = "(e:c)"; }
        void operator()(const hilti::ctor::Bool& b) { result = "(c:b)"; }

        std::optional<std::string> result;
    };

    auto root = ast();
    auto v = Visitor();

    v.result.reset();
    v.dispatch(root);
    REQUIRE(v.result);
    REQUIRE(*v.result == "(mo)");

    v.result.reset();
    v.dispatch(root.children()[0]);
    REQUIRE(v.result);
    REQUIRE(*v.result == "(id)");

    v.result.reset();
    v.dispatch(root.children()[1]);
    REQUIRE(! v.result);
}

TEST_CASE("Visitor, pre-order, no result, constant nodes") {
    struct Visitor : hilti::visitor::PreOrder<void, Visitor>, hilti::type::Visitor {
        using base_t::base_t;

        result_t operator()(const hilti::Module& m) { x += "(mo)"; }
        result_t operator()(const hilti::ID& id) { x += "(id)"; }
        result_t operator()(const hilti::Type& t, const_position_t i) { x += "(t)"; }
        result_t operator()(const hilti::type::String& s, hilti::type::Visitor::position_t&) override { x += "(ts)"; }
        result_t operator()(const hilti::type::SignedInteger& i, hilti::type::Visitor::position_t&) override {
            x += "(ti)";
        }
        result_t operator()(const hilti::expression::Ctor& c, const_position_t i) { x += "(e:c)"; }
        result_t operator()(const hilti::ctor::Bool& b) { x += "(c:b)"; }

        void testDispatch(iterator_t::Position i) {
            if ( ! dispatch(i) )
                x += "-";
            x += ",";
        }
        void testDispatch(const_iterator_t::Position i) {
            if ( ! dispatch(i) )
                x += "-";
            x += ",";
        }

        std::string x;
        const std::string expected =
            "(mo),(id),-,-,(id),(ts)(t),-,-,(id),(ti)(t),-,-,(id),(t),-,-,(id),(t),-,-,(id),(t),(e:c),(c:b),(t),";
    };

    // Node an rvalue.
    auto root0 = ast();
    auto v = Visitor();
    for ( auto i : v.walk(root0) )
        v.testDispatch(i);

    CHECK(v.x == v.expected);

    // Node a lvalue.
    auto root1 = ast();
    auto v2 = Visitor();
    for ( auto i : v2.walk(root1) )
        v2.testDispatch(i);

    CHECK(v2.x == v2.expected);

    // Node a const value.
    const auto root2 = ast();
    auto v3 = Visitor();
    for ( auto i : v3.walk(root2) )
        v3.testDispatch(i);

    CHECK(v3.x == v3.expected);

    // Visitor an rvalue.
    auto root4 = ast();
    int c = 0;

    auto walk = Visitor().walk(root4);
    std::for_each(walk.begin(), walk.end(), [&](auto&&) { ++c; });

    CHECK(c == 25);
}

TEST_CASE("Visitor, pre-order, constant nodes") {
    struct Visitor : hilti::visitor::PreOrder<void, Visitor>, hilti::type::Visitor {
        using base_t::base_t;

        void operator()(const hilti::Module& m) { x += "(mo)"; }
        void operator()(const hilti::ID& id) { x += "(id)"; }
        void operator()(const hilti::Type& t, const_position_t i) { x += "(t)"; }
        void operator()(const hilti::type::String& s, hilti::type::Visitor::position_t&) override { x += "(ts)"; }
        void operator()(const hilti::type::SignedInteger& i, hilti::type::Visitor::position_t&) override {
            x += "(ti)";
        }
        void operator()(const hilti::expression::Ctor& c, const_position_t i) { x += "(e:c)"; }
        void operator()(const hilti::ctor::Bool& b) { x += "(c:b)"; }

        void testDispatch(const_iterator_t::Position i) {
            if ( ! dispatch(i) )
                x += "-";
            x += ",";
        }

        std::string x;
        const std::string expected =
            "(mo),(id),-,-,(id),(ts)(t),-,-,(id),(ti)(t),-,-,(id),(t),-,-,(id),(t),-,-,(id),(t),(e:c),(c:b),(t),";
    };


    auto root = ast();
    auto v = Visitor();
    for ( auto i : v.walk(root) )
        v.testDispatch(i);

    CHECK(v.x == v.expected);
}

TEST_CASE("Visitor, post-order") {
    struct Visitor : hilti::visitor::PostOrder<void, Visitor>, hilti::type::Visitor {
        using base_t::base_t;

        result_t operator()(const hilti::Module& m) { x += "(mo)"; }
        result_t operator()(const hilti::ID& id) { x += "(id)"; }
        result_t operator()(const hilti::Type& t) { x += "(t)"; }
        result_t operator()(const hilti::type::String& s, hilti::type::Visitor::position_t&) override { x += "(ts)"; }
        result_t operator()(const hilti::type::SignedInteger& i, hilti::type::Visitor::position_t&) override {
            x += "(ti)";
        }
        result_t operator()(const hilti::expression::Ctor& c) { x += "(e:c)"; }
        result_t operator()(const hilti::ctor::Bool& b) { x += "(c:b)"; }

        void testDispatch(iterator_t::Position i) {
            if ( ! dispatch(i) )
                x += "-";
            x += ",";
        }
        void testDispatch(const_iterator_t::Position i) {
            if ( ! dispatch(i) )
                x += "-";
            x += ",";
        }

        std::string x;
        const std::string expected =
            "(id),-,(id),(ts)(t),-,-,(id),(ti)(t),-,-,(id),(t),-,-,(id),(t),-,-,(id),(t),(t),(c:b),(e:c),-,(mo),";
    };

    auto root = ast();
    auto v = Visitor();
    for ( auto i : v.walk(root) )
        v.testDispatch(i);

    CHECK(v.x == v.expected);
}

TEST_CASE("Retrieve parent") {
    struct Visitor : hilti::visitor::PreOrder<void, Visitor>, hilti::type::Visitor {
        void operator()(const hilti::type::SignedInteger& n, hilti::type::Visitor::position_t& i) override {
            x = i.parent().typename_();
        }

        std::string x;
    };

    auto root = ast();
    auto v = Visitor();
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    REQUIRE(v.x == "hilti::declaration::Type");
}

TEST_CASE("Find specific parent") {
    struct Visitor : hilti::visitor::PreOrder<void, Visitor>, hilti::type::Visitor {
        void operator()(const hilti::type::SignedInteger& n, hilti::type::Visitor::position_t& i) override {
            x = to_node(i.findParent<hilti::Module>()).typename_();
        }
        std::string x;
    };

    auto root = ast();
    auto v = Visitor();
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    REQUIRE(v.x == "hilti::Module");
}

TEST_CASE("Copy node by value") {
    hilti::Type t = hilti::type::Vector(hilti::type::String());
    CHECK(! hilti::type::isConstant(t));
    auto t2 = hilti::type::constant(t._clone().as<hilti::Type>());
    auto t3 = hilti::type::constant(t);
    auto t4(hilti::type::constant(t));
    CHECK(hilti::type::isConstant(t2));
    CHECK(hilti::type::isConstant(t3));
    CHECK(hilti::type::isConstant(t4));
    CHECK(! hilti::type::isConstant(t));
}

TEST_CASE("Sort node errors") {
    hilti::node::Error e1 = {.message = "A", .location = hilti::Location("foo.txt:1"), .context = {"xxx"}};
    hilti::node::Error e2 = {.message = "A", .location = hilti::Location("foo.txt:1"), .context = {"yyy"}};
    hilti::node::Error e3 = {.message = "A", .location = hilti::Location("foo.txt:2"), .context = {"xxx"}};
    hilti::node::Error e4 = {.message = "B", .location = hilti::Location("foo.txt:1"), .context = {"yyy"}};
    hilti::node::Error e5 = {.message = "B", .location = hilti::Location("xxx.txt:1"), .context = {"yyy"}};

    // e1 == e1
    CHECK(! (e1 < e1));
    CHECK(! (e1 < e1));

    CHECK(e1 < e3);
    CHECK(! (e3 < e1));

    // e1 == e2
    CHECK(! (e1 < e2));
    CHECK(! (e2 < e1));

    CHECK(e1 < e4);
    CHECK(! (e4 < e1));

    CHECK(e3 < e4);
    CHECK(! (e4 < e3));

    CHECK(e4 < e5);
    CHECK(! (e5 < e4));
}

TEST_SUITE_END();
