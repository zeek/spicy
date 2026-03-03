// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/visitor.h>

using namespace hilti;

visitor::MutatingVisitorBase::MutatingVisitorBase(ASTContext* ctx, logging::DebugStream dbg)
    : _context(ctx), _dbg(std::move(dbg)) {}

void visitor::MutatingVisitorBase::replaceNode(Node* old, Node* new_, const std::string& msg) {
    assert(old && old->parent());

    auto location = util::fmt("[%s] ", old->location().dump(true));
    std::string msg_;

    if ( ! msg.empty() )
        msg_ = util::fmt(" (%s)", msg);

    if ( new_ )
        HILTI_DEBUG(_dbg, util::fmt("%s%s \"%s\" -> %s \"%s\"%s", location, old->typename_(), old->printRaw(),
                                    new_->typename_(), new_->printRaw(), msg_))
    else
        HILTI_DEBUG(_dbg, util::fmt("%s%s \"%s\" -> null%s", location, old->typename_(), old->printRaw(), msg_))

    old->parent()->replaceChild(_context, old, new_);
    _modified = true;
}

void visitor::MutatingVisitorBase::replaceNodeWithChild(Node* old, Node* new_, const std::string& msg) {
    assert(new_);
    assert(old->parent());
    assert(new_->parent());
    assert(new_->parent()->hasChild(new_, true));

    auto location = util::fmt("[%s] ", old->location().dump(true));
    std::string msg_;

    if ( ! msg.empty() )
        msg_ = util::fmt(" (%s)", msg);

    HILTI_DEBUG(_dbg, util::fmt("%s%s \"%s\" -> %s \"%s\"%s", location, old->typename_(), old->printRaw(),
                                new_->typename_(), new_->printRaw(), msg_))

    new_->removeFromParent(); // will leave parent in undefined state, which is fine because the parent will be detached
                              // next (and eventually deleted).
    old->parent()->replaceChild(_context, old, new_);
    _modified = true;
}

void visitor::MutatingVisitorBase::removeNode(Node* old, const std::string& msg) {
    if ( ! old->parent() )
        return;

    replaceNode(old, nullptr, msg);
}

void visitor::MutatingVisitorBase::recordChange(const Node* old, Node* changed, const std::string& msg) {
    auto location = util::fmt("[%s] ", old->location().dump(true));
    std::string msg_;

    if ( ! msg.empty() )
        msg_ = util::fmt(" (%s)", msg);

    HILTI_DEBUG(_dbg, util::fmt("%s%s \"%s\" -> %s \"%s\"%s", location, old->typename_(), old->printRaw(),
                                changed->typename_(), *changed, msg_))
    _modified = true;
}

void visitor::MutatingVisitorBase::recordChange(const Node* old, const std::string& msg) {
    auto location = util::fmt("[%s] ", old->location().dump(true));
    HILTI_DEBUG(_dbg, util::fmt("%s%s \"%s\" -> %s", location, old->typename_(), old->printRaw(), msg))
    _modified = true;
}

ASTContext* visitor::MutatingVisitorBase::contextFromBuilder(Builder* builder) { return builder->context(); }
