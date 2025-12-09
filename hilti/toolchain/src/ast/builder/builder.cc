// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/compiler/driver.h>

using namespace hilti;
using util::fmt;

const Options& Builder::options() const { return context()->compilerContext()->options(); }

Expression* Builder::addTmp(const std::string& prefix, QualifiedType* t, const Expressions& args) {
    int n = 0;

    if ( auto i = _tmps().find(prefix); i != _tmps().end() )
        n = i->second;

    ID tmp;

    if ( ++n == 1 )
        tmp = ID(fmt(HILTI_INTERNAL_ID("%s"), prefix));
    else
        tmp = ID(fmt(HILTI_INTERNAL_ID("%s_%d"), prefix, n));

    _tmps()[prefix] = n;
    block()->_add(context(), local(tmp, t, args));
    return id(tmp);
}

Expression* Builder::addTmp(const std::string& prefix, Expression* init) {
    int n = 0;

    if ( auto i = _tmps().find(prefix); i != _tmps().end() )
        n = i->second;

    ID tmp;

    if ( ++n == 1 )
        tmp = ID(fmt(HILTI_INTERNAL_ID("%s"), prefix));
    else
        tmp = ID(fmt(HILTI_INTERNAL_ID("%s_%d"), prefix, n));

    _tmps()[prefix] = n;
    block()->_add(context(), local(tmp, init));
    return id(tmp);
}

Expression* Builder::addTmp(const std::string& prefix, QualifiedType* t, Expression* init) {
    int n = 0;

    if ( auto i = _tmps().find(prefix); i != _tmps().end() )
        n = i->second;

    ID tmp;

    if ( ++n == 1 )
        tmp = ID(fmt(HILTI_INTERNAL_ID("%s"), prefix));
    else
        tmp = ID(fmt(HILTI_INTERNAL_ID("%s_%d"), prefix, n));

    _tmps()[prefix] = n;
    block()->_add(context(), local(tmp, t, init));
    return id(tmp);
}

void Builder::addDebugMsg(std::string_view stream, std::string_view fmt, Expressions args) {
    if ( ! context()->driver()->options().debug )
        return;

    Expression* call_ = nullptr;

    if ( args.empty() )
        call_ = call("hilti::debug", {stringLiteral(stream), stringLiteral(fmt)});
    else if ( args.size() == 1 ) {
        auto* msg = modulo(stringLiteral(fmt), args.front());
        call_ = call("hilti::debug", {stringLiteral(stream), msg});
    }
    else {
        auto* msg = modulo(stringLiteral(fmt), tuple(args));
        call_ = call("hilti::debug", {stringLiteral(stream), msg});
    }

    block()->_add(context(), statementExpression(call_, call_->meta()));
}

void Builder::addDebugIndent(std::string_view stream) {
    if ( ! context()->driver()->options().debug )
        return;

    auto* call_ = call("hilti::debugIndent", {stringLiteral(stream)});
    block()->_add(context(), statementExpression(call_));
}

void Builder::addDebugDedent(std::string_view stream) {
    if ( ! context()->driver()->options().debug )
        return;

    auto* call_ = call("hilti::debugDedent", {stringLiteral(stream)});
    block()->_add(context(), statementExpression(call_));
}

void Builder::setLocation(const Location& l) {
    block()->_add(context(), statementSetLocation(stringLiteral(l.dump())));
}

Expression* Builder::startProfiler(std::string_view name, Expression* size) {
    if ( ! context()->driver()->options().enable_profiling )
        return {};

    // Note the name of the temp must not clash what HILTI's code generator
    // picks for profiler that it instantiates itself. We do not currently keep
    // those namespace separate.
    Expression* profiler = nullptr;

    if ( size )
        profiler = call("hilti::profiler_start", {stringLiteral(name), size});
    else
        profiler = call("hilti::profiler_start", {stringLiteral(name)});

    return addTmp("prof", profiler);
}

void Builder::stopProfiler(Expression* profiler, Expression* size) {
    if ( ! context()->driver()->options().enable_profiling )
        return;

    if ( size )
        addCall("hilti::profiler_stop", {profiler, size});
    else
        addCall("hilti::profiler_stop", {profiler});
}
