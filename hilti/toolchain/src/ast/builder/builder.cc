// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <exception>

#include <hilti/ast/builder/builder.h>
#include <hilti/compiler/driver.h>

using namespace hilti;
using util::fmt;

const Options& Builder::options() const {
    assert(context()->driver());
    return context()->driver()->options();
}

ExpressionPtr Builder::addTmp(const std::string& prefix, const QualifiedTypePtr& t, const Expressions& args) {
    int n = 0;

    if ( auto i = _tmps().find(prefix); i != _tmps().end() )
        n = i->second;

    ID tmp;

    if ( ++n == 1 )
        tmp = ID(fmt("__%s", prefix));
    else
        tmp = ID(fmt("__%s_%d", prefix, n));

    _tmps()[prefix] = n;
    block()->_add(context(), local(tmp, t, args));
    return id(tmp);
}

ExpressionPtr Builder::addTmp(const std::string& prefix, const ExpressionPtr& init) {
    int n = 0;

    if ( auto i = _tmps().find(prefix); i != _tmps().end() )
        n = i->second;

    ID tmp;

    if ( ++n == 1 )
        tmp = ID(fmt("__%s", prefix));
    else
        tmp = ID(fmt("__%s_%d", prefix, n));

    _tmps()[prefix] = n;
    block()->_add(context(), local(tmp, init));
    return id(tmp);
}

ExpressionPtr Builder::addTmp(const std::string& prefix, const QualifiedTypePtr& t, const ExpressionPtr& init) {
    int n = 0;

    if ( auto i = _tmps().find(prefix); i != _tmps().end() )
        n = i->second;

    ID tmp;

    if ( ++n == 1 )
        tmp = ID(fmt("__%s", prefix));
    else
        tmp = ID(fmt("__%s_%d", prefix, n));

    _tmps()[prefix] = n;
    block()->_add(context(), local(tmp, t, init));
    return id(tmp);
}

void Builder::addDebugMsg(std::string_view stream, std::string_view fmt, Expressions args) {
    if ( ! context()->driver()->options().debug )
        return;

    ExpressionPtr call_;

    if ( args.empty() )
        call_ = call("hilti::debug", {stringLiteral(stream), stringLiteral(fmt)});
    else if ( args.size() == 1 ) {
        auto msg = modulo(stringLiteral(fmt), std::move(args.front()));
        call_ = call("hilti::debug", {stringLiteral(stream), std::move(msg)});
    }
    else {
        auto msg = modulo(stringLiteral(fmt), tuple(args));
        call_ = call("hilti::debug", {stringLiteral(stream), std::move(msg)});
    }

    block()->_add(context(), statementExpression(call_, call_->meta()));
}

void Builder::addDebugIndent(std::string_view stream) {
    if ( ! context()->driver()->options().debug )
        return;

    auto call_ = call("hilti::debugIndent", {stringLiteral(stream)});
    block()->_add(context(), statementExpression(call_));
}

void Builder::addDebugDedent(std::string_view stream) {
    if ( ! context()->driver()->options().debug )
        return;

    auto call_ = call("hilti::debugDedent", {stringLiteral(stream)});
    block()->_add(context(), statementExpression(call_));
}

void Builder::setLocation(const Location& l) {
    block()->_add(context(), statementSetLocation(stringLiteral(l.dump())));
}

std::optional<ExpressionPtr> Builder::startProfiler(std::string_view name) {
    if ( ! context()->driver()->options().enable_profiling )
        return {};

    // Note the name of the temp must not clash what HILTI's code generator
    // picks for profiler that it instantiates itself. We do not currently keep
    // those namespace separate.
    return addTmp("prof", call("hilti::profiler_start", {stringLiteral(name)}));
}

void Builder::stopProfiler(ExpressionPtr profiler) {
    if ( ! context()->driver()->options().enable_profiling )
        return;

    addCall("hilti::profiler_stop", {std::move(profiler)});
}
