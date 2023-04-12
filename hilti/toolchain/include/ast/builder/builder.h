// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/builder/declaration.h>
#include <hilti/ast/builder/expression.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/statements/all.h>

namespace hilti {
class Context;
} // namespace hilti

namespace hilti::builder {

class Builder {
public:
    Builder(std::weak_ptr<hilti::Context> context)
        : _context(std::move(context)), _our_block(statement::Block()), _block(*_our_block) {}

    Statement block() {
        assert(_our_block);
        return *_our_block;
    }

    auto context() const { return _context.lock(); }

    Expression addTmp(const std::string& prefix, const Expression& init);
    Expression addTmp(const std::string& prefix, const Type& t, const std::vector<Expression>& args = {});
    Expression addTmp(const std::string& prefix, const Type& t, const Expression& init);

    void addLocal(ID id, Type t, Meta m = Meta()) {
        _block._add(builder::local(std::move(id), std::move(t), std::move(m)));
    }

    void addLocal(ID id, Expression init, Meta m = Meta()) {
        _block._add(builder::local(std::move(id), std::move(init), std::move(m)));
    }

    void addLocal(ID id, Type t, Expression init, Meta m = Meta()) {
        _block._add(builder::local(std::move(id), std::move(t), std::move(init), std::move(m)));
    }

    void addLocal(ID id, Type t, std::vector<hilti::Expression> args, Meta m = Meta()) {
        _block._add(builder::local(std::move(id), std::move(t), std::move(args), std::move(m)));
    }

    void addExpression(const Expression& expr) { _block._add(statement::Expression(expr, expr.meta())); }

    void addAssert(Expression cond, std::string msg, Meta m = Meta()) {
        _block._add(statement::Assert(std::move(cond), builder::string(std::move(msg)), std::move(m)));
    }

    void addAssign(Expression dst, Expression src, const Meta& m = Meta()) {
        _block._add(statement::Expression(builder::assign(std::move(dst), std::move(src), m), m));
    }

    void addSumAssign(Expression dst, Expression src, const Meta& m = Meta()) {
        _block._add(statement::Expression(builder::sumAssign(std::move(dst), std::move(src), m), m));
    }

    void addAssign(ID dst, Expression src, const Meta& m = Meta()) {
        _block._add(statement::Expression(builder::assign(builder::id(std::move(dst)), std::move(src), m), m));
    }

    void addBreak(Meta m = Meta()) { _block._add(statement::Break(std::move(m))); }

    void addContinue(Meta m = Meta()) { _block._add(statement::Continue(std::move(m))); }

    void addSumAssign(ID dst, Expression src, const Meta& m = Meta()) {
        _block._add(statement::Expression(builder::sumAssign(builder::id(std::move(dst)), std::move(src), m), m));
    }

    void addCall(ID id, const std::vector<Expression>& v, const Meta& m = Meta()) {
        _block._add(statement::Expression(builder::call(std::move(id), v, m), m));
    }

    void addMemberCall(Expression self, const ID& id, const std::vector<Expression>& v, const Meta& m = Meta()) {
        _block._add(statement::Expression(builder::memberCall(std::move(self), id, v, m), m));
    }

    void addComment(std::string comment,
                    hilti::statement::comment::Separator separator = hilti::statement::comment::Separator::Before,
                    const Meta& m = Meta()) {
        comment = util::replace(comment, "\n", "");
        _block._add(statement::Comment(std::move(comment), separator, m));
    }

    void addReturn(Expression e, Meta m = Meta()) { _block._add(statement::Return(std::move(e), std::move(m))); }

    void addReturn(Ctor c, const Meta& m = Meta()) {
        _block._add(statement::Return(expression::Ctor(std::move(c), m), m));
    }

    void addReturn(Meta m = Meta()) { _block._add(statement::Return(std::move(m))); }

    void addThrow(Expression excpt, Meta m = Meta()) { _block._add(statement::Throw(std::move(excpt), std::move(m))); }
    void addRethrow(Meta m = Meta()) { _block._add(statement::Throw(std::move(m))); }

    void addDebugMsg(const std::string& stream, const std::string& fmt, std::vector<Expression> args = {});
    void addDebugIndent(const std::string& stream);
    void addDebugDedent(const std::string& stream);

    void addPrint(const std::vector<Expression>& exprs) { addCall("hilti::print", exprs); }
    void addPrint(const Expression& expr) { addCall("hilti::print", {expr}); }

    auto addWhile(const statement::Declaration& init, Expression cond, Meta m = Meta()) {
        _block._add(statement::While(init.declaration(), std::move(cond), statement::Block(), {}, std::move(m)));
        return newBuilder(lastStatement<statement::While>()._bodyNode());
    }

    auto addWhile(Expression cond, Meta m = Meta()) {
        _block._add(statement::While(std::move(cond), statement::Block(), {}, std::move(m)));
        return newBuilder(lastStatement<statement::While>()._bodyNode());
    }

    auto addWhileElse(const statement::Declaration& init, Expression cond, Meta m = Meta()) {
        _block._add(statement::While(init.declaration(), std::move(cond), statement::Block(), statement::Block(),
                                     std::move(m)));
        return std::make_pair(newBuilder(lastStatement<statement::While>()._bodyNode()),
                              newBuilder(lastStatement<statement::While>()._elseNode()));
    }

    auto addWhileElse(Expression cond, Meta m = Meta()) {
        _block._add(statement::While(std::move(cond), statement::Block(), statement::Block(), std::move(m)));
        return std::make_pair(newBuilder(lastStatement<statement::While>()._bodyNode()),
                              newBuilder(lastStatement<statement::While>()._elseNode()));
    }

    auto addIf(const statement::Declaration& init, Expression cond, Meta m = Meta()) {
        _block._add(statement::If(init.declaration(), std::move(cond), statement::Block(), {}, std::move(m)));
        return newBuilder(lastStatement<statement::If>()._trueNode());
    }

    auto addIf(const statement::Declaration& init, Meta m = Meta()) {
        _block._add(statement::If(init.declaration(), {}, statement::Block(), {}, std::move(m)));
        return newBuilder(lastStatement<statement::If>()._trueNode());
    }

    auto addIf(Expression cond, Meta m = Meta()) {
        _block._add(statement::If(std::move(cond), statement::Block(), {}, std::move(m)));
        return newBuilder(lastStatement<statement::If>()._trueNode());
    }

    auto addIfElse(const statement::Declaration& init, Expression cond, Meta m = Meta()) {
        _block._add(
            statement::If(init.declaration(), std::move(cond), statement::Block(), statement::Block(), std::move(m)));
        return std::make_pair(newBuilder(lastStatement<statement::If>()._trueNode()),
                              newBuilder(lastStatement<statement::If>()._falseNode()));
    }

    auto addIfElse(const statement::Declaration& init, Meta m = Meta()) {
        _block._add(statement::If(init.declaration(), {}, statement::Block(), statement::Block(), std::move(m)));
        return std::make_pair(newBuilder(lastStatement<statement::If>()._trueNode()),
                              newBuilder(lastStatement<statement::If>()._falseNode()));
    }

    auto addIfElse(Expression cond, Meta m = Meta()) {
        _block._add(statement::If(std::move(cond), statement::Block(), statement::Block(), std::move(m)));
        return std::make_pair(newBuilder(lastStatement<statement::If>()._trueNode()),
                              newBuilder(lastStatement<statement::If>()._falseNode()));
    }

    auto addBlock(Meta m = Meta()) {
        _block._add(statement::Block({}, std::move(m)));
        return newBuilder(_block._lastStatementNode());
    }

    class SwitchProxy {
    public:
        SwitchProxy(Builder* b, statement::Switch& s) : _builder(b), _switch(s) {} // NOLINT

        auto addCase(Expression expr, Meta m = Meta()) { return _addCase({std::move(expr)}, std::move(m)); }

        auto addCase(std::vector<Expression> exprs, Meta m = Meta()) {
            return _addCase(std::move(exprs), std::move(m));
        }

        auto addDefault(Meta m = Meta()) { return _addCase({}, std::move(m)); }

    private:
        std::shared_ptr<Builder> _addCase(std::vector<Expression> exprs, Meta m = Meta()) {
            _switch._addCase(statement::switch_::Case(std::move(exprs), statement::Block(), std::move(m)));
            return _builder->newBuilder(_switch._lastCaseNode().as<statement::switch_::Case>()._bodyNode());
        }

        Builder* _builder;
        statement::Switch& _switch;
    };

    auto addSwitch(Expression cond, const Meta& m = Meta()) {
        _block._add(statement::Switch(std::move(cond), {}, m));
        return SwitchProxy(this, lastStatement<statement::Switch>());
    }

    auto addSwitch(const statement::Declaration& cond, Meta m = Meta()) {
        _block._add(statement::Switch(cond.declaration(), {}, std::move(m)));
        return SwitchProxy(this, lastStatement<statement::Switch>());
    }

    void setLocation(const Location& l);

    class TryProxy {
    public:
        TryProxy(Builder* b, statement::Try& s) : _builder(b), _try(&s) {} //NOLINT(google-runtime-references)

        auto addCatch(declaration::Parameter p, Meta m = Meta()) {
            _try->_addCatch(statement::try_::Catch(std::move(p), statement::Block(), std::move(m)));
            return _builder->newBuilder(_try->_lastCatchNode().as<statement::try_::Catch>()._bodyNode());
        }

        auto addCatch(Meta m = Meta()) {
            _try->_addCatch(statement::try_::Catch(statement::Block(), std::move(m)));
            return _builder->newBuilder(_try->_lastCatchNode().as<statement::try_::Catch>()._bodyNode());
        }

        TryProxy(const TryProxy&) = default;
        TryProxy(TryProxy&&) = default;
        TryProxy() = delete;
        ~TryProxy() = default;
        TryProxy& operator=(const TryProxy&) = default;
        TryProxy& operator=(TryProxy&&) noexcept = default;

    private:
        Builder* _builder;
        statement::Try* _try;
    };

    auto addTry(Meta m = Meta()) {
        _block._add(statement::Try(statement::Block(), {}, std::move(m)));
        return std::make_pair(newBuilder(lastStatement<statement::Try>()._bodyNode()),
                              TryProxy(this, lastStatement<statement::Try>()));
    }

    bool empty() const { return _block.statements().empty() && _tmps.empty(); }

    std::optional<Expression> startProfiler(const std::string& name);
    void stopProfiler(Expression profiler);

private:
    friend class SwitchProxy;

    Builder(std::weak_ptr<hilti::Context> context, Statement& s) // NOLINT
        : _context(std::move(context)), _block(s.as<statement::Block>()) {}

    template<typename T>
    T& lastStatement() {
        return _block._lastStatementNode().as<T>();
    }

    std::shared_ptr<Builder> newBuilder(Node& n) { // NOLINT
        return std::shared_ptr<Builder>(new Builder(_context, n.template as<Statement>()));
    }

    std::weak_ptr<hilti::Context> _context;
    std::optional<statement::Block> _our_block;
    statement::Block& _block;

    std::map<std::string, int> _tmps;
};

} // namespace hilti::builder
