// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
// @TEST-REQUIRES: using-build-directory
// @TEST-EXEC: test-visitor >&2
//
// Note: This is compiled through CMakeLists.txt.

#include <doctest/doctest.h>

#include <algorithm>
#include <optional>
#include <sstream>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/type.h>
#include <hilti/hilti.h>

static auto ast() {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = hilti::Builder(ctx.get());
    auto s = builder.declarationType(hilti::ID("s"),
                                     builder.qualifiedType(builder.typeString(), hilti::Constness::NonConst));
    auto i32 = builder.declarationType(hilti::ID("i32"), builder.qualifiedType(builder.typeSignedInteger(32),
                                                                               hilti::Constness::NonConst));
    auto d =
        builder.declarationType(hilti::ID("d"), builder.qualifiedType(builder.typeReal(), hilti::Constness::NonConst));
    auto e = builder.declarationLocalVariable(hilti::ID("e"),
                                              builder.qualifiedType(builder.typeVoid(), hilti::Constness::Const));
    auto c = builder.declarationLocalVariable(hilti::ID("c"),
                                              builder.qualifiedType(builder.typeBool(), hilti::Constness::NonConst),
                                              builder.expressionCtor(builder.ctorBool(true)));

    hilti::Declarations x = {s, i32, d, e, c};
    auto uid = hilti::declaration::module::UID("test", "/tmp/test.hlt");
    auto m = builder.declarationModule(uid, {}, x);
    return std::make_pair(std::move(ctx), m);
}

TEST_SUITE_BEGIN("Visitor");

TEST_CASE("Single-shot, result, constant node") {
    struct Visitor : hilti::visitor::PreOrder {
        void operator()(hilti::ASTRoot* n) final { result = "(ro)"; }
        void operator()(hilti::declaration::Module* n) final { result = "(mo)"; }
        void operator()(hilti::QualifiedType* n) final { result = "(qt)"; }
        void operator()(hilti::UnqualifiedType* n) final { result = "(ut)"; }
        void operator()(hilti::type::String* n) final { result = "(ts)"; }
        void operator()(hilti::type::SignedInteger* n) final { result = "(ti)"; }
        void operator()(hilti::expression::Ctor* n) final { result = "(e:c)"; }
        void operator()(hilti::ctor::Bool* n) final { result = "(c:b)"; }
        void operator()(hilti::statement::Block* n) final { result = "(s:b)"; }

        std::optional<std::string> result;
    };

    auto [ctx, module] = ast();
    auto v = Visitor();

    v.result.reset();
    v.dispatch(module);
    REQUIRE(v.result);
    REQUIRE(*v.result == "(mo)");

    v.result.reset();
    v.dispatch(module->child(0));
    REQUIRE(v.result);
    REQUIRE(*v.result == "(s:b)");

    v.result.reset();
    v.dispatch(module->child(1));
    REQUIRE(! v.result);
}

TEST_CASE("Visitor, pre-order") {
    struct Visitor : hilti::visitor::PreOrder {
        void operator()(hilti::declaration::Module* m) final { x += "(mo)"; }
        void operator()(hilti::QualifiedType* t) final { x += "(qt)"; }
        void operator()(hilti::type::String* s) final { x += "(ts)"; }
        void operator()(hilti::type::SignedInteger* i) final { x += "(ti)"; }
        void operator()(hilti::expression::Ctor* c) final { x += "(e:c)"; }
        void operator()(hilti::ctor::Bool* b) final { x += "(c:b)"; }
        void operator()(hilti::statement::Block* n) final { x += "(s:b)"; }

        void testDispatch(const hilti::NodePtr& i) {
            auto old = x.size();
            dispatch(i);
            if ( x.size() == old )
                x += hilti::util::fmt("[%s]", i->typename_());

            x += ",";
        }

        std::string x;
        const std::string expected =
            "(mo),(s:b),[declaration::Type],(qt),(ts),[AttributeSet],[declaration::Type],(qt),(ti),[AttributeSet],["
            "declaration::Type],(qt),[type::Real],[AttributeSet],[declaration::LocalVariable],(qt),[type::Void],["
            "declaration::LocalVariable],(qt),[type::Bool],(e:c),(c:b),(qt),[type::Bool],";
    };

    auto [ctx, module] = ast();
    auto v = Visitor();
    for ( auto i : hilti::visitor::range(v, module) )
        v.testDispatch(i);

    CHECK(v.x == v.expected);
}

TEST_CASE("Visitor, pre-order") {
    struct Visitor : hilti::visitor::PostOrder {
        void operator()(hilti::declaration::Module* m) final { x += "(mo)"; }
        void operator()(hilti::QualifiedType* t) final { x += "(qt)"; }
        void operator()(hilti::type::String* s) final { x += "(ts)"; }
        void operator()(hilti::type::SignedInteger* i) final { x += "(ti)"; }
        void operator()(hilti::expression::Ctor* c) final { x += "(e:c)"; }
        void operator()(hilti::ctor::Bool* b) final { x += "(c:b)"; }
        void operator()(hilti::statement::Block* n) final { x += "(s:b)"; }

        void testDispatch(const hilti::NodePtr& i) {
            auto old = x.size();
            dispatch(i);
            if ( x.size() == old )
                x += hilti::util::fmt("[%s]", i->typename_());

            x += ",";
        }

        std::string x;
        const std::string expected =
            "(s:b),(ts),(qt),[AttributeSet],[declaration::Type],(ti),(qt),[AttributeSet],[declaration::Type],[type::"
            "Real],(qt),[AttributeSet],[declaration::Type],[type::Void],(qt),[declaration::LocalVariable],[type::Bool],"
            "(qt),[type::Bool],(qt),(c:b),(e:c),[declaration::LocalVariable],(mo),";
    };

    auto [ctx, module] = ast();
    auto v = Visitor();
    for ( auto i : hilti::visitor::range(v, module) )
        v.testDispatch(i);

    CHECK(v.x == v.expected);
}

TEST_CASE("Retrieve parent") {
    struct Visitor : hilti::visitor::PreOrder {
        void operator()(hilti::statement::Block* n) final { x += n->parent()->typename_() + "|"; }
        void operator()(hilti::type::SignedInteger* n) final { x += n->parent(2)->typename_() + "|"; }
        std::string x;
    };

    auto [ctx, module] = ast();
    auto v = Visitor();
    hilti::visitor::visit(v, module);

    REQUIRE(v.x == "declaration::Module|declaration::Type|");
}

TEST_CASE("Find specific parent") {
    struct Visitor : hilti::visitor::PreOrder {
        void operator()(hilti::type::SignedInteger* n) final {
            x = n->parent<hilti::declaration::Module>()->typename_();
        }
        std::string x;
    };

    auto [ctx, module] = ast();
    auto v = Visitor();
    hilti::visitor::visit(v, module);

    REQUIRE(v.x == "declaration::Module");
}

TEST_CASE("Copy node by value on insert") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = hilti::Builder(ctx.get());

    std::shared_ptr<hilti::Declaration> d =
        builder.declarationType(hilti::ID("x"),
                                builder.qualifiedType(builder.typeString(), hilti::Constness::NonConst));
    auto uid = hilti::declaration::module::UID("m", "/tmp/m.hlt");
    auto m = builder.declarationModule(uid, {}, {d});
    REQUIRE(m->declarations().size() == 1);
    CHECK(m->declarations()[0] == d); // same object was inserted, not copied
    m->add(ctx.get(), d);
    REQUIRE(m->declarations().size() == 2);
    CHECK(m->declarations()[1] != d);                                      // new object was inserted, copied
    CHECK(m->declarations()[0]->print() == m->declarations()[1]->print()); // some content
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
