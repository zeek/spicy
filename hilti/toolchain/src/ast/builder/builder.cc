// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <exception>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/enum.h>
#include <hilti/base/util.h>
#include <hilti/compiler/context.h>

using namespace hilti;
using namespace hilti::builder;

using util::fmt;

Expression Builder::addTmp(const std::string& prefix, const Type& t, const std::vector<Expression>& args) {
    int n = 0;

    if ( auto i = _tmps.find(prefix); i != _tmps.end() )
        n = i->second;

    ID tmp;

    if ( ++n == 1 )
        tmp = ID(fmt("__%s", prefix));
    else
        tmp = ID(fmt("__%s_%d", prefix, n));

    _tmps[prefix] = n;
    _block._add(builder::local(tmp, t, args));
    return builder::id(tmp);
}

Expression Builder::addTmp(const std::string& prefix, const Expression& init) {
    int n = 0;

    if ( auto i = _tmps.find(prefix); i != _tmps.end() )
        n = i->second;

    ID tmp;

    if ( ++n == 1 )
        tmp = ID(fmt("__%s", prefix));
    else
        tmp = ID(fmt("__%s_%d", prefix, n));

    _tmps[prefix] = n;
    _block._add(builder::local(tmp, init));
    return builder::id(tmp);
}

Expression Builder::addTmp(const std::string& prefix, const Type& t, const Expression& init) {
    int n = 0;

    if ( auto i = _tmps.find(prefix); i != _tmps.end() )
        n = i->second;

    ID tmp;

    if ( ++n == 1 )
        tmp = ID(fmt("__%s", prefix));
    else
        tmp = ID(fmt("__%s_%d", prefix, n));

    _tmps[prefix] = n;
    _block._add(builder::local(tmp, t, init));
    return builder::id(tmp);
}

void Builder::addDebugMsg(const std::string& stream, const std::string& fmt, std::vector<Expression> args) {
    if ( ! context()->options().debug )
        return;

    Expression call;

    if ( args.empty() )
        call = builder::call("hilti::debug", {builder::string(stream), builder::string(fmt)});
    else if ( args.size() == 1 ) {
        auto msg = builder::modulo(builder::string(fmt), std::move(args.front()));
        call = builder::call("hilti::debug", {builder::string(stream), std::move(msg)});
    }
    else {
        auto msg = builder::modulo(builder::string(fmt), builder::tuple(args));
        call = builder::call("hilti::debug", {builder::string(stream), std::move(msg)});
    }

    _block._add(statement::Expression(call, call.meta()));
}

void Builder::addDebugIndent(const std::string& stream) {
    if ( ! context()->options().debug )
        return;

    auto call = builder::call("hilti::debugIndent", {builder::string(stream)});
    _block._add(statement::Expression(std::move(call)));
}

void Builder::addDebugDedent(const std::string& stream) {
    if ( ! context()->options().debug )
        return;

    auto call = builder::call("hilti::debugDedent", {builder::string(stream)});
    _block._add(statement::Expression(std::move(call)));
}

void Builder::setLocation(const Location& l) { _block._add(statement::SetLocation(builder::string(l.render()))); }

std::optional<Expression> Builder::startProfiler(const std::string& name) {
    if ( ! context()->options().enable_profiling )
        return {};

    // Note the name of the temp must not clash what HILTI's code generator
    // picks for profiler that it instantiates itself. We do not currently keep
    // those namespace separate.
    return addTmp("prof", builder::call("hilti::profiler_start", {builder::string(name)}));
}

void Builder::stopProfiler(Expression profiler) {
    if ( ! context()->options().enable_profiling )
        return;

    addCall("hilti::profiler_stop", {std::move(profiler)});
}
