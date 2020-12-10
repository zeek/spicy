// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/property.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/coerced.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/operators/struct.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/regexp.h>
#include <hilti/base/logger.h>
#include <hilti/global.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/operators/all.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/codegen/grammar-builder.h>
#include <spicy/compiler/detail/codegen/grammar.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;

using hilti::util::fmt;

namespace builder = hilti::builder;

namespace {

// Visitor that runs only once the 1st time AST transformation is triggered.
struct VisitorPassInit : public hilti::visitor::PreOrder<void, VisitorPassInit> {
    VisitorPassInit(CodeGen* cg, hilti::Module* module) : cg(cg), module(module) {}
    CodeGen* cg;
    hilti::Module* module;
    ID module_id = ID("<no module>");
    bool modified = false;

    std::vector<std::pair<NodeRef, Node>> new_nodes;

    template<typename T>
    void replaceNode(position_t* p, T&& n) {
        auto x = p->node;
        p->node = std::forward<T>(n);
        p->node.setOriginalNode(module->preserve(x));
        modified = true;
    }

    void finalize() {
        if ( new_nodes.empty() )
            return;

        for ( auto& n : new_nodes )
            *n.first = std::move(n.second);

        new_nodes.clear();
        modified = true;
    }

    void operator()(const hilti::declaration::Property& m) { cg->recordModuleProperty(m); }

    void operator()(const hilti::Module& m) {
        module_id = m.id();
        cg->addDeclaration(builder::import("hilti", m.meta()));
        cg->addDeclaration(builder::import("spicy_rt", m.meta()));
    }

    void operator()(const hilti::declaration::Type& t, position_t p) {
        auto u = t.type().tryAs<type::Unit>();

        if ( ! u )
            return;

        auto nu = type::setTypeID(*u, ID(module_id, t.id())).as<type::Unit>();

        if ( t.linkage() == declaration::Linkage::Public && ! nu.isPublic() )
            nu = type::Unit::setPublic(nu, true);

        // Create unit property items from global module items where the unit
        // does not provide an overriding one.
        std::vector<type::unit::Item> ni;
        for ( auto& p : cg->moduleProperties() ) {
            if ( ! u->propertyItem(p.id()) )
                ni.emplace_back(type::unit::item::Property(p.id(), *p.expression(), {}, true, p.meta()));
        }

        if ( ni.size() )
            nu = type::Unit::addItems(nu, ni);

        auto nt = hilti::declaration::Type::setType(t, nu);
        replaceNode(&p, nt);

        // Build the unit's grammar.
        if ( auto r = cg->grammarBuilder()->run(nu, &p.node, cg); ! r ) {
            hilti::logger().error(r.error().description(), p.node.location());
            return;
        }

        auto ns = cg->compileUnit(nu, false);
        auto attrs = AttributeSet::add(t.attributes(), Attribute("&on-heap"));
        auto nd = hilti::declaration::Type(nt.id(), ns, attrs, nt.linkage(), nt.meta());
        replaceNode(&p, nd);
    }
};

// Visitor that runs multiple times whenever a transformation pass is triggered.
struct VisitorPassIterate : public hilti::visitor::PreOrder<void, VisitorPassIterate> {
    VisitorPassIterate(CodeGen* cg, hilti::Module* module) : cg(cg), module(module) {}
    CodeGen* cg;
    hilti::Module* module;
    ID module_id = ID("<no module>");
    bool modified = false;

    template<typename T>
    void replaceNode(position_t* p, T&& n) {
        auto x = p->node;
        p->node = std::forward<T>(n);
        p->node.setOriginalNode(module->preserve(x));
        modified = true;
    }

    Expression argument(const Expression& args, unsigned int i, std::optional<Expression> def = {}) {
        auto ctor = args.as<hilti::expression::Ctor>().ctor();

        if ( auto x = ctor.tryAs<hilti::ctor::Coerced>() )
            ctor = x->coercedCtor();

        auto value = ctor.as<hilti::ctor::Tuple>().value();

        if ( i < value.size() )
            return ctor.as<hilti::ctor::Tuple>().value()[i];

        if ( def )
            return *def;

        hilti::logger().internalError(fmt("missing argument %d", i));
    }

    void replaceNode(position_t* p, Node&& n) {
        auto x = p->node;

        if ( x.location() && ! n.location() ) {
            auto m = n.meta();
            m.setLocation(x.location());
            n.setMeta(std::move(m));
        }

        p->node = std::move(n);
        p->node.setOriginalNode(module->preserve(x));
        modified = true;
    }

    void operator()(const declaration::UnitHook& n, position_t p) {
        const auto& unit_type = n.unitType();
        const auto& hook = n.unitHook().hook();

        if ( ! unit_type )
            // Not resolved yet.
            return;

        auto func = cg->compileHook(*unit_type, ID(*unit_type->typeID(), n.unitHook().id()), {}, hook.isForEach(),
                                    hook.isDebug(), hook.type().parameters(), hook.body(), hook.priority(), n.meta());

        replaceNode(&p, std::move(func));
    }

    result_t operator()(const operator_::bitfield::Member& n, position_t p) {
        auto id = n.op1().as<hilti::expression::Member>().id();
        auto idx = n.op0().type().as<spicy::type::Bitfield>().bitsIndex(id);
        assert(idx);
        auto x = builder::index(n.op0(), *idx, n.meta());
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::unit::Offset& n, position_t p) {
        auto begin = builder::deref(builder::member(n.op0(), ID("__begin")));
        auto cur = builder::deref(builder::member(n.op0(), ID("__position")));
        replaceNode(&p, builder::difference(cur, begin));
    }

    result_t operator()(const operator_::unit::Input& n, position_t p) {
        auto begin = builder::deref(builder::member(n.op0(), ID("__begin")));
        replaceNode(&p, begin);
    }

    result_t operator()(const operator_::unit::SetInput& n, position_t p) {
        auto cur = builder::member(n.op0(), ID("__position_update"));
        replaceNode(&p, builder::assign(cur, argument(n.op2(), 0)));
    }

    result_t operator()(const operator_::unit::Backtrack& n, position_t p) {
        auto x = builder::call("spicy_rt::backtrack", {});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::unit::ConnectFilter& n, position_t p) {
        auto x = builder::call("spicy_rt::filter_connect", {n.op0(), argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::unit::Forward& n, position_t p) {
        auto x = builder::call("spicy_rt::filter_forward", {n.op0(), argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::unit::ForwardEod& n, position_t p) {
        auto x = builder::call("spicy_rt::filter_forward_eod", {n.op0()});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::Close& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "close", {});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::Connect& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "connect", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::ConnectMIMETypeBytes& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "connect_mime_type", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::ConnectMIMETypeString& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "connect_mime_type", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::ConnectFilter& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "connect_filter", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::Gap& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "gap", {argument(n.op2(), 0), argument(n.op2(), 1)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::SequenceNumber& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "sequence_number", {});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::SetAutoTrim& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "set_auto_trim", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::SetInitialSequenceNumber& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "set_initial_sequence_number", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::SetPolicy& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "set_policy", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::SizeValue& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "size", {});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::SizeReference& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "size", {});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::Skip& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "skip", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::Trim& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "trim", {argument(n.op2(), 0)});
        replaceNode(&p, std::move(x));
    }

    result_t operator()(const operator_::sink::Write& n, position_t p) {
        auto x = builder::memberCall(n.op0(), "write",
                                     {argument(n.op2(), 0), argument(n.op2(), 1, builder::null()),
                                      argument(n.op2(), 2, builder::null())});
        replaceNode(&p, std::move(x));
    }

    void operator()(const statement::Print& n, position_t p) {
        auto exprs = n.expressions();

        switch ( exprs.size() ) {
            case 0: {
                auto call = builder::call("hilti::print", {builder::string("")});
                replaceNode(&p, hilti::statement::Expression(call, p.node.location()));
                break;
            }

            case 1: {
                auto call = builder::call("hilti::print", std::move(exprs));
                replaceNode(&p, hilti::statement::Expression(call, p.node.location()));
                break;
            }

            default: {
                auto call = builder::call("hilti::printValues", {builder::tuple(std::move(exprs))});
                replaceNode(&p, hilti::statement::Expression(call, p.node.location()));
                break;
            }
        }
    }

    void operator()(const statement::Stop& n, position_t p) {
        auto b = builder::Builder(cg->context());
        b.addAssign(builder::id("__stop"), builder::bool_(true), n.meta());
        b.addReturn(n.meta());
        replaceNode(&p, b.block());
    }

    void operator()(const type::ResolvedID& n, position_t p) {
        // Some of the original name/type bindings may have become invalid,
        // flag them to be resolved again.

        if ( n.isValid() )
            return;

        replaceNode(&p, builder::typeByID(n.id()));
    }

    void operator()(const type::Sink& n, position_t p) {
        // Strong reference (instead of value reference) so that copying unit
        // instances doesn't copy the sink.
        auto sink = hilti::type::StrongReference(builder::typeByID("spicy_rt::Sink", n.meta()));
        replaceNode(&p, Type(sink));
    }
};


} // anonymous namespace

bool CodeGen::compileModule(hilti::Node* root, bool init, hilti::Unit* u) {
    hilti::util::timing::Collector _("spicy/compiler/codegen");

    _hilti_unit = u;
    _root = root;

    bool modified = false;

    if ( init ) {
        auto v = VisitorPassInit(this, &root->as<hilti::Module>());
        for ( auto i : v.walk(root) )
            v.dispatch(i);

        v.finalize();

        modified = (modified || v.modified);

        if ( hilti::logger().errors() )
            goto done;

        if ( _new_decls.size() ) {
            for ( const auto& n : _new_decls )
                hiltiModule()->add(n);

            _new_decls.clear();
            modified = true;
        }
    }

    {
        auto v = VisitorPassIterate(this, &root->as<hilti::Module>());
        for ( auto i : v.walk(root) )
            v.dispatch(i);

        modified = (modified || v.modified);
    }

done:
    _hilti_unit = nullptr;
    _root = nullptr;

    return modified;
}

std::optional<hilti::declaration::Function> CodeGen::compileHook(
    const type::Unit& unit, const ID& id, std::optional<std::reference_wrapper<const type::unit::item::Field>> field,
    bool foreach, bool debug, std::vector<type::function::Parameter> params, std::optional<hilti::Statement> body,
    std::optional<Expression> priority, const hilti::Meta& meta) {
    if ( debug && ! options().debug )
        return {};

    std::optional<Type> item_type;
    std::optional<Type> original_item_type;

    if ( field ) {
        if ( ! field->get().parseType().isA<type::Void>() ) {
            item_type = field->get().itemType();
            original_item_type = field->get().originalType();
        }
    }
    else {
        // Try to locate field by ID.
        if ( auto i = unit.field(id.local()) ) {
            auto f = i->as<type::unit::item::Field>();
            if ( ! f.parseType().isA<type::Void>() ) {
                item_type = f.itemType();
                original_item_type = f.originalType();
            }
        }
    }

    if ( foreach ) {
        // We have no easy way to get to the resolved element type, so defer
        // that until we can derive it manually.
        auto ut = Type(hilti::type::UnresolvedID(*unit.typeID()));

        auto cb = [id](Node& n) -> Type {
            auto t = type::effectiveType(n.as<Type>());

            auto rt = t.tryAs<type::ValueReference>();
            if ( ! rt )
                return type::unknown;

            auto st = rt->dereferencedType().tryAs<type::Struct>();
            if ( ! st )
                return type::unknown;

            return st->field(id.local())->auxType()->as<type::Vector>().elementType();
        };

        auto element_type = type::Computed(ut, cb);
        params.push_back({ID("__dd"), element_type, hilti::type::function::parameter::Kind::In, {}});
        params.push_back({ID("__stop"), type::Bool(), hilti::type::function::parameter::Kind::InOut, {}});
    }
    else if ( item_type ) {
        params.push_back({ID("__dd"), *item_type, hilti::type::function::parameter::Kind::In, {}});

        if ( original_item_type && original_item_type->isA<type::RegExp>() )
            params.push_back({ID("__captures"),
                              builder::typeByID("hilti::Captures"),
                              hilti::type::function::parameter::Kind::In,
                              {}});
    };

    std::string hid;
    Type result;

    if ( id.local().str() == "0x25_print" ) {
        // Special-case: We simply translate this into HITLI's __str__ hook.
        result = hilti::type::Optional(hilti::type::String());
        hid = "__str__";
    }
    else {
        result = hilti::type::Void();
        hid = fmt("__on_%s%s", id.local(), (foreach ? "_foreach" : ""));
    }

    if ( ! id.namespace_().empty() )
        hid = fmt("%s::%s", id.namespace_(), hid);

    auto rt = hilti::type::function::Result(std::move(result));
    auto ft = hilti::type::Function(std::move(rt), params, hilti::type::function::Flavor::Hook, meta);

    std::optional<AttributeSet> attrs;

    if ( priority )
        attrs = AttributeSet::add(attrs, Attribute("&priority", *priority));

    auto f = hilti::Function(ID(hid), std::move(ft), std::move(body), hilti::function::CallingConvention::Standard,
                             std::move(attrs), meta);
    return hilti::declaration::Function(std::move(f), hilti::declaration::Linkage::Struct, meta);
}

hilti::Module* CodeGen::hiltiModule() const {
    if ( ! _hilti_unit )
        hilti::logger().internalError("not compiling a HILTI unit");

    return &_root->as<hilti::Module>();
}

hilti::Unit* CodeGen::hiltiUnit() const {
    if ( ! _hilti_unit )
        hilti::logger().internalError("not compiling a HILTI unit");

    return _hilti_unit;
}

NodeRef CodeGen::preserveNode(Expression x) { return hiltiModule()->preserve(std::move(x)); }

NodeRef CodeGen::preserveNode(Statement x) { return hiltiModule()->preserve(std::move(x)); }

NodeRef CodeGen::preserveNode(Type x) { return hiltiModule()->preserve(std::move(x)); }
