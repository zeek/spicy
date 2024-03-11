// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/visitor.h>

using namespace hilti;

visitor::MutatingVisitorBase::MutatingVisitorBase(ASTContext* ctx, logging::DebugStream dbg)
    : _context(ctx), _dbg(std::move(dbg)) {}

void visitor::MutatingVisitorBase::replaceNode(Node* old, Node* new_, const std::string& msg) {
    auto location = util::fmt("[%s] ", old->location().dump(true));
    std::string msg_;

    if ( ! msg.empty() )
        msg_ = util::fmt(" (%s)", msg);

    if ( new_ )
        HILTI_DEBUG(_dbg, util::fmt("%s%s \"%s\" -> %s \"%s\"%s", location, old->typename_(), *old, new_->typename_(),
                                    *new_, msg_))
    else
        HILTI_DEBUG(_dbg, util::fmt("%s%s \"%s\" -> null%s", location, old->typename_(), *old, msg_))

    assert(old->parent());
    if ( new_ && new_->parent() )
        new_->parent()->removeChild(new_);

    old->parent()->replaceChild(_context, old, new_);
    _modified = true;
}

void visitor::MutatingVisitorBase::recordChange(const Node* old, Node* changed, const std::string& msg) {
    auto location = util::fmt("[%s] ", old->location().dump(true));
    std::string msg_;

    if ( ! msg.empty() )
        msg_ = util::fmt(" (%s)", msg);

    HILTI_DEBUG(_dbg, util::fmt("%s%s \"%s\" -> %s \"%s\"%s", location, old->typename_(), *old, changed->typename_(),
                                *changed, msg_))
    _modified = true;
}

void visitor::MutatingVisitorBase::recordChange(const Node* old, const std::string& msg) {
    auto location = util::fmt("[%s] ", old->location().dump(true));
    HILTI_DEBUG(_dbg, util::fmt("%s%s \"%s\" -> %s", location, old->typename_(), *old, msg))
    _modified = true;
}

void visitor::MutatingVisitorBase::recordChange(const std::string& msg) {
    HILTI_DEBUG(_dbg, msg);
    _modified = true;
}

ASTContext* visitor::MutatingVisitorBase::contextFromBuilder(Builder* builder) { return builder->context(); }
