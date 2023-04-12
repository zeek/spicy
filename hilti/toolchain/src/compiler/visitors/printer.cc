// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <cstdio>

#include <hilti/ast/all.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/plugin.h>
#include <hilti/compiler/printer.h>

using namespace hilti;
using util::fmt;

// Global state storing any scopes we are currently in during printing.
// Maintaining this globally isn't great, but because of various independent
// `printAST()` calls happening recursively through `operator<<` and `fmt()`,
// we can't easily pass this state around.
static std::vector<ID> _scopes = {""};

static const ID& _currentScope() { return _scopes.back(); }
static void _pushScope(ID id) { _scopes.push_back(std::move(id)); }
static void _popScope() { _scopes.pop_back(); }

static std::string renderOperator(operator_::Kind kind, const std::vector<std::string>& ops) {
    switch ( kind ) {
        case operator_::Kind::Add: return fmt("add %s[%s]", ops[0], ops[1]);
        case operator_::Kind::Begin: return fmt("begin(%s)", ops[0]);
        case operator_::Kind::BitAnd: return fmt("%s & %s", ops[0], ops[1]);
        case operator_::Kind::BitOr: return fmt("%s | %s", ops[0], ops[1]);
        case operator_::Kind::BitXor: return fmt("%s ^ %s", ops[0], ops[1]);
        case operator_::Kind::Call: return fmt("%s%s", ops[0], ops[1]);
        case operator_::Kind::Cast: return fmt("cast<%s>(%s)", ops[1], ops[0]);
        case operator_::Kind::CustomAssign: return fmt("%s = %s", ops[0], ops[1]);
        case operator_::Kind::DecrPostfix: return fmt("%s--", ops[0]);
        case operator_::Kind::DecrPrefix: return fmt("--%s", ops[0]);
        case operator_::Kind::Delete: return fmt("delete %s[%s]", ops[0], ops[1]);
        case operator_::Kind::Deref: return fmt("(*%s)", ops[0]);
        case operator_::Kind::Difference: return fmt("%s - %s", ops[0], ops[1]);
        case operator_::Kind::DifferenceAssign: return fmt("%s -= %s", ops[0], ops[1]);
        case operator_::Kind::Division: return fmt("%s / %s", ops[0], ops[1]);
        case operator_::Kind::DivisionAssign: return fmt("%s /= %s", ops[0], ops[1]);
        case operator_::Kind::Equal: return fmt("%s == %s", ops[0], ops[1]);
        case operator_::Kind::End: return fmt("end(%s)", ops[0]);
        case operator_::Kind::Greater: return fmt("%s > %s", ops[0], ops[1]);
        case operator_::Kind::GreaterEqual: return fmt("%s >= %s", ops[0], ops[1]);
        case operator_::Kind::HasMember: return fmt("%s?.%s", ops[0], ops[1]);
        case operator_::Kind::In: return fmt("%s in %s", ops[0], ops[1]);
        case operator_::Kind::IncrPostfix: return fmt("%s++", ops[0]);
        case operator_::Kind::IncrPrefix: return fmt("++%s", ops[0]);
        case operator_::Kind::Index: return fmt("%s[%s]", ops[0], ops[1]);
        case operator_::Kind::IndexAssign: return fmt("%s[%s] = %s", ops[0], ops[1], ops[2]);
        case operator_::Kind::Lower: return fmt("%s < %s", ops[0], ops[1]);
        case operator_::Kind::LowerEqual: return fmt("%s <= %s", ops[0], ops[1]);
        case operator_::Kind::Member: return fmt("%s.%s", ops[0], ops[1]);
        case operator_::Kind::MemberCall: return fmt("%s.%s%s", ops[0], ops[1], ops[2]);
        case operator_::Kind::Modulo: return fmt("%s %% %s", ops[0], ops[1]);
        case operator_::Kind::Multiple: return fmt("%s * %s", ops[0], ops[1]);
        case operator_::Kind::MultipleAssign: return fmt("%s *= %s", ops[0], ops[1]);
        case operator_::Kind::Negate: return fmt("~%s", ops[0]);
        case operator_::Kind::New: return fmt("new %s%s", ops[0], ops[1]);
        case operator_::Kind::Pack: return fmt("pack%s", ops[0]);
        case operator_::Kind::Power: return fmt("%s ** %s", ops[0], ops[1]);
        case operator_::Kind::ShiftLeft: return fmt("%s << %s", ops[0], ops[1]);
        case operator_::Kind::ShiftRight: return fmt("%s >> %s", ops[0], ops[1]);
        case operator_::Kind::SignNeg: return fmt("-%s", ops[0]);
        case operator_::Kind::SignPos: return fmt("+%s", ops[0]);
        case operator_::Kind::Size: return fmt("|%s|", ops[0]);
        case operator_::Kind::Sum: return fmt("%s + %s", ops[0], ops[1]);
        case operator_::Kind::SumAssign: return fmt("%s += %s", ops[0], ops[1]);
        case operator_::Kind::TryMember: return fmt("%s.?%s", ops[0], ops[1]);
        case operator_::Kind::Unequal: return fmt("%s != %s", ops[0], ops[1]);
        case operator_::Kind::Unpack: return fmt("unpack<%s>(%s)", ops[0], ops[1]);
        case operator_::Kind::Unknown: logger().internalError("\"unknown\" operator");
        case operator_::Kind::Unset: return fmt("unset %s", ops[0]);
    }

    util::cannot_be_reached();
}

static std::string renderExpressionType(const Expression& e) {
    auto const_ = (e.isConstant() && type::isMutable(e.type()) ? "const " : "");
    return fmt("%s%s", const_, e.type());
}

static std::string renderOperand(operator_::Operand op, const node::Range<Expression>& exprs) {
    auto t = operator_::type(op.type, exprs, exprs);
    std::string s = (t ? fmt("%s", *t) : "<no-type>");

    if ( op.default_ )
        s = fmt("%s=%s", s, *op.default_);

    if ( op.optional || op.default_ )
        s = fmt("[%s]", s);

    return s;
}

namespace {

struct Visitor : visitor::PreOrder<void, Visitor> {
    Visitor(printer::Stream& out) : out(out) {} // NOLINT

    void printFunctionType(const type::Function& ftype, const std::optional<ID>& id) {
        if ( ftype.isWildcard() ) {
            out << "<function>";
            return;
        }

        if ( ftype.flavor() != type::function::Flavor::Standard )
            out << to_string(ftype.flavor()) << ' ';

        out << ftype.result() << ' ';

        if ( id )
            out << *id;

        out << '(';
        out << std::make_pair(ftype.parameters(), ", ");
        out << ')';
    }

    void printDoc(const std::optional<DocString>& doc) {
        if ( doc && *doc ) {
            out.emptyLine();
            doc->render(out);
        }
    }

    auto linkage(declaration::Linkage l) {
        switch ( l ) {
            case declaration::Linkage::Init: return "init ";
            case declaration::Linkage::PreInit: return "preinit ";
            case declaration::Linkage::Struct: return "method ";
            case declaration::Linkage::Private: return ""; // That's the default.
            case declaration::Linkage::Public: return "public ";
            default: util::cannot_be_reached();
        }
    }

    auto const_(const Type& t) {
        return (out.isCompact() && type::isConstant(t) && type::isMutable(t)) ? "const " : "";
    }

    void operator()(const Attribute& n) {
        out << n.tag();

        if ( n.hasValue() )
            out << "=" << n.value();
    }

    void operator()(const AttributeSet& n) {
        bool first = true;
        for ( const auto& a : n.attributes() ) {
            if ( ! first )
                out << ' ';
            else
                first = false;

            out << a;
        }
    }

    void operator()(const type::function::Result& n) { out << n.type(); }

    void operator()(const Function& n) {
        if ( n.callingConvention() != function::CallingConvention::Standard )
            out << to_string(n.callingConvention()) << ' ';

        printFunctionType(n.ftype(), n.id());

        if ( n.attributes() )
            out << ' ' << std::make_pair(n.attributes()->attributes(), " ");

        if ( n.body() )
            out << ' ' << *n.body();
        else
            out << ';' << out.newline();
    }

    void operator()(const ID& n) {
        if ( n.namespace_() == _currentScope() )
            out << std::string(n.local());
        else
            out << std::string(n);
    }

    void operator()(const Module& n) {
        printDoc(n.documentation());
        out.beginLine();
        out << "module " << n.id() << " {" << out.newline();
        out.endLine();

        _pushScope(n.id());

        auto printDecls = [&](const auto& decls) {
            for ( const auto& d : decls )
                out << Declaration(d);

            if ( decls.size() )
                out.emptyLine();
        };

        printDecls(node::filter(n.declarations(),
                                [](const auto& d) { return d.template isA<declaration::ImportedModule>(); }));
        printDecls(node::filter(n.declarations(), [](const auto& d) { return d.template isA<declaration::Type>(); }));
        printDecls(
            node::filter(n.declarations(), [](const auto& d) { return d.template isA<declaration::Constant>(); }));
        printDecls(node::filter(n.declarations(),
                                [](const auto& d) { return d.template isA<declaration::GlobalVariable>(); }));
        printDecls(
            node::filter(n.declarations(), [](const auto& d) { return d.template isA<declaration::Function>(); }));

        for ( const auto& s : n.statements().statements() )
            out << s;

        if ( ! n.statements().statements().empty() )
            out.emptyLine();

        _popScope();

        out.beginLine();
        out << "}";
        out.endLine();
    }

    ////// Ctors

    void operator()(const ctor::Address& n) { out << n.value(); }

    void operator()(const ctor::Bool& n) { out << (n.value() ? "True" : "False"); }

    void operator()(const ctor::Bytes& n) { out << "b\"" << util::escapeUTF8(n.value(), true) << '"'; }

    void operator()(const ctor::Coerced& n) { out << n.originalCtor(); }

    void operator()(const ctor::Default& n) {
        out << "default<" << n.type() << ">(" << std::make_pair(n.typeArguments(), ", ") << ")";
    }

    void operator()(const ctor::Enum& n, position_t p) {
        assert(n.type().typeID());
        out << *n.type().typeID() << "::" << n.value().id();
    }

    void operator()(const ctor::Error& n) { out << "error(\"" << n.value() << "\")"; }

    void operator()(const ctor::Interval& n) { out << "interval_ns(" << n.value().nanoseconds() << ")"; }

    void operator()(const ctor::List& n) { out << '[' << std::make_pair(n.value(), ", ") << ']'; }

    void operator()(const ctor::Map& n) {
        auto elems = node::transform(n.value(), [](const auto& e) { return fmt("%s: %s", e.key(), e.value()); });
        out << "map(" << std::make_pair(elems, ", ") << ')';
    }

    void operator()(const ctor::Network& n) { out << n.value(); }

    void operator()(const ctor::Null& n) { out << "Null"; }

    void operator()(const ctor::Optional& n) {
        if ( n.value() )
            out << *n.value();
        else
            out << "Null";
    }

    void operator()(const ctor::Port& n) { out << n.value(); }

    void operator()(const ctor::Real& n) {
        // We use hexformat for lossless serialization. Older platforms like
        // centos7 have inconsistent support for that in iostreams so we use
        // C99 snprintf instead.
        constexpr size_t size = 256;
        char buf[size];
        std::snprintf(buf, size, "%a", n.value());
        out << buf;
    }

    void operator()(const ctor::StrongReference& n) { out << "Null"; }

    void operator()(const ctor::RegExp& n) {
        out << std::make_pair(util::transform(n.value(), [](auto p) { return fmt("/%s/", p); }), " |");
    }

    void operator()(const ctor::Result& n) {
        if ( n.value() )
            out << *n.value();
        else
            out << *n.error();
    }

    void operator()(const ctor::Set& n) { out << "set(" << std::make_pair(n.value(), ", ") << ')'; }

    void operator()(const ctor::SignedInteger& n) {
        if ( n.width() < 64 )
            out << fmt("int%d(%" PRId64 ")", n.width(), n.value());
        else
            out << n.value();
    }

    void operator()(const ctor::Stream& n) { out << "stream(" << util::escapeUTF8(n.value(), true) << ')'; }

    void operator()(const ctor::String& n) { out << '"' << util::escapeUTF8(n.value(), true) << '"'; }

    void operator()(const ctor::Struct& n) {
        out << "[";

        bool first = true;
        for ( const auto& f : n.fields() ) {
            if ( ! first )
                out << ", ";
            else
                first = false;

            out << '$' << f.id() << "=" << f.expression();
        }

        out << "]";
    }

    void operator()(const ctor::Time& n) { out << "time_ns(" << n.value().nanoseconds() << ")"; }

    void operator()(const ctor::Tuple& n) { out << '(' << std::make_pair(n.value(), ", ") << ')'; }

    void operator()(const ctor::UnsignedInteger& n) {
        if ( n.width() < 64 )
            out << fmt("uint%d(%" PRId64 ")", n.width(), n.value());
        else
            out << n.value();
    }

    void operator()(const ctor::Vector& n) { out << "vector(" << std::make_pair(n.value(), ", ") << ')'; }

    void operator()(const ctor::WeakReference& n) { out << "Null"; }

    void operator()(const ctor::ValueReference& n) { out << "value_ref(" << n.expression() << ')'; }

    ////// Declarations

    void operator()(const declaration::Constant& n) {
        printDoc(n.documentation());
        out.beginLine();
        out << linkage(n.linkage()) << "const ";
        out << n.type();
        out << ' ' << n.id() << " = " << n.value() << ';';
        out.endLine();
    }

    void operator()(const declaration::Expression& n) { out << n.expression(); }

    void operator()(const declaration::Field& n) {
        out << "    ";

        if ( auto ft = n.type().tryAs<type::Function>() ) {
            out << to_string(ft->flavor()) << " ";

            if ( n.callingConvention() != function::CallingConvention::Standard )
                out << to_string(n.callingConvention()) << ' ';

            out << ft->result().type() << " " << n.id() << "(" << std::make_pair(ft->parameters(), ", ") << ")";
        }

        else
            out << n.type() << ' ' << n.id();

        if ( n.attributes() )
            out << ' ' << *n.attributes();

        if ( auto f = n.inlineFunction(); f && f->body() ) {
            const auto& block = f->body()->tryAs<statement::Block>();
            if ( block && block->statements().empty() ) {
                out << " {}";
                out.endLine();
            }
            else if ( block && block->statements().size() == 1 ) {
                auto old_compact = out.setCompact(true);
                out << " { " << *block->statements().begin() << " }";
                out.setCompact(old_compact);
                out.endLine();
            }
            else {
                out.incrementIndent();
                out << ' ' << *f->body();
                out.decrementIndent();
            }
        }
        else
            out << ";" << out.newline();
    }

    void operator()(const declaration::Parameter& n) {
        auto kind = [&](auto k) {
            switch ( k ) {
                case declaration::parameter::Kind::Copy: return "copy ";
                case declaration::parameter::Kind::In: return "";
                case declaration::parameter::Kind::InOut: return "inout ";
                case declaration::parameter::Kind::Unknown: logger().internalError("parameter kind not set");
            }

            util::cannot_be_reached();
        };

        out << kind(n.kind()) << n.type() << ' ' << n.id();

        if ( n.default_() )
            out << " = " << *n.default_();

        if ( const auto attrs = n.attributes(); attrs && ! attrs->attributes().empty() )
            out << ' ' << *attrs;
    }

    void operator()(const declaration::Function& n) {
        const auto& func = n.function();

        if ( ! func.body() ) {
            printDoc(n.documentation());
            out.beginLine();
            out << "declare ";
        }
        else {
            out.emptyLine();
            printDoc(n.documentation());
            out.beginLine();
        }

        out << linkage(n.linkage());

        if ( n.linkage() != declaration::Linkage::Struct )
            out << "function ";

        out << n.function();
    }

    void operator()(const declaration::ImportedModule& n) {
        out.beginLine();
        if ( n.scope() )
            out << "import " << n.id() << " from " << *n.scope() << ';';
        else
            out << "import " << n.id() << ';';

        out.endLine();
    }

    void operator()(const declaration::Type& n) {
        printDoc(n.documentation());
        out.beginLine();
        for ( const auto& comment : n.meta().comments() )
            out << "# " << comment << '\n';
        out << linkage(n.linkage()) << "type " << n.id() << " = ";
        out.setExpandSubsequentType(true);
        out << n.type();

        if ( n.attributes() )
            out << ' ' << *n.attributes();

        out << ';';
        out.endLine();
    }

    void operator()(const declaration::LocalVariable& n) {
        // Will be printed through a statement, hence no outer formatting.
        out << "local ";
        out << n.type();
        out << ' ' << n.id();

        if ( n.typeArguments().size() )
            out << '(' << std::make_pair(n.typeArguments(), ", ") << ')';

        if ( n.init() )
            out << " = " << *n.init();
    }

    void operator()(const declaration::GlobalVariable& n) {
        printDoc(n.documentation());
        out.beginLine();
        out << linkage(n.linkage()) << "global ";
        out << n.type();
        out << ' ' << n.id();

        if ( n.typeArguments().size() )
            out << '(' << std::make_pair(n.typeArguments(), ", ") << ')';

        if ( n.init() )
            out << " = " << *n.init();

        out << ';';
        out.endLine();
    }

    ////// Expressions

    void operator()(const expression::Assign& n) { out << n.target() << " = " << n.source(); }

    void operator()(const expression::BuiltinFunction& n) {
        out << n.name() << "(" << util::join(node::transform(n.arguments(), [](auto& p) { return fmt("%s", p); }), ", ")
            << ")";
    }

    void operator()(const expression::Coerced& n) { out << n.expression(); }

    void operator()(const expression::Ctor& n) { out << n.ctor(); }

    void operator()(const expression::Grouping& n) { out << '(' << n.expression() << ')'; }

    result_t operator()(const expression::Keyword& n) {
        switch ( n.kind() ) {
            case expression::keyword::Kind::Self: out << "self"; break;
            case expression::keyword::Kind::DollarDollar: out << "$$"; break;
            case expression::keyword::Kind::Captures:
                out << "$@"; // this is technically not valid source code; we don't expose this to users
                break;
            case expression::keyword::Kind::Scope: out << "$scope"; break;
        }
    }

    result_t operator()(const expression::ListComprehension& n) {
        out << '[' << n.output() << " for " << n.local() << " in " << n.input();

        if ( n.condition() )
            out << " if " << *n.condition();

        out << ']';
    }

    result_t operator()(const expression::LogicalAnd& n) { out << n.op0() << " && " << n.op1(); }

    result_t operator()(const expression::LogicalNot& n) { out << "! " << n.expression(); }

    result_t operator()(const expression::LogicalOr& n) { out << n.op0() << " || " << n.op1(); }

    result_t operator()(const expression::Member& n) { out << n.id(); }

    result_t operator()(const expression::Move& n) { out << "move(" << n.expression() << ")"; }

    void operator()(const expression::ResolvedID& n) { out << n.id(); }

    result_t operator()(const expression::Ternary& n) {
        out << n.condition() << " ? " << n.true_() << " : " << n.false_();
    }

    result_t operator()(const expression::Type_& n) {
        if ( auto id = n.typeValue().typeID() )
            out << *id;
        else
            out << n.typeValue();
    }

    result_t operator()(const expression::TypeInfo& n) { out << "typeinfo(" << n.expression() << ")"; }

    result_t operator()(const expression::TypeWrapped& n) { out << n.expression(); }

    void operator()(const expression::UnresolvedID& n) { out << n.id(); }

    void operator()(const expression::Void& n) {
        out << "<void expression>"; // Shouldn't really happen.
    }

    ////// Statements

    void operator()(const statement::Assert& n) {
        out.beginLine();

        if ( n.expectsException() )
            out << "assert-exception ";
        else
            out << "assert ";

        out << n.expression();
        if ( n.message() )
            out << " : " << *n.message();
        out << ";";
        out.endLine();
    }

    void operator()(const statement::Block& n) {
        if ( out.indent() == 0 || n.statements().size() > 1 )
            out << "{";

        out.endLine();
        out.incrementIndent();

        const auto& stmts = n.statements();
        for ( const auto&& [i, s] : util::enumerate(stmts) ) {
            out.setPositionInBlock(i == 0, i == (stmts.size() - 1));

            if ( s.isA<statement::Block>() )
                out.beginLine();

            out << s;

            if ( s.isA<statement::Block>() )
                out.endLine();
        }

        out.decrementIndent();

        if ( out.indent() == 0 || n.statements().size() > 1 ) {
            out.beginLine();
            out << "}";
            out.endLine();
        }
    }

    void operator()(const statement::Break& n) {
        out.beginLine();
        out << "break;";
        out.endLine();
    }

    void operator()(const statement::Continue& n) {
        out.beginLine();
        out << "continue;";
        out.endLine();
    }

    void operator()(const statement::Comment& n) {
        if ( (n.separator() == hilti::statement::comment::Separator::Before ||
              n.separator() == hilti::statement::comment::Separator::BeforeAndAfter) &&
             ! out.isFirstInBlock() )
            out.emptyLine();

        out.beginLine();
        out << "# " << n.comment();
        out.endLine();

        if ( (n.separator() == hilti::statement::comment::Separator::After ||
              n.separator() == hilti::statement::comment::Separator::BeforeAndAfter) &&
             ! out.isLastInBlock() )
            out.emptyLine();
    }

    void operator()(const statement::Declaration& n) {
        out.beginLine();
        out << n.declaration() << ';';
        out.endLine();
    }

    void operator()(const statement::Expression& n) {
        out.beginLine();
        out << n.expression() << ';';
        out.endLine();
    }

    void operator()(const statement::For& n) {
        out.emptyLine();
        out.beginLine();
        out << "for ( " << n.local().id() << " in " << n.sequence() << " ) " << n.body();
        out.endLine();
    }

    void operator()(const statement::If& n) {
        out.emptyLine();
        out.beginLine();
        out << "if ( ";

        if ( auto e = n.init() )
            out << Declaration(*e) << "; ";

        if ( auto e = n.condition() )
            out << *e;

        out << " ) " << n.true_();

        if ( n.false_() ) {
            out.beginLine();
            out << "else " << *n.false_();
        }

        out.endLine();
    }

    void operator()(const statement::SetLocation& n) {
        out.beginLine();
        out << "# " << *n.expression();
        out.endLine();
    }

    void operator()(const statement::Return& n) {
        out.beginLine();
        out << "return";

        if ( auto e = n.expression() )
            out << ' ' << *e;

        out << ';';
        out.endLine();
    }

    void operator()(const statement::Switch& n) {
        out.emptyLine();
        out.beginLine();
        out << "switch ( ";

        if ( const auto& cond = n.condition(); cond.id().str() != "__x" )
            out << cond;
        else
            out << *cond.init();

        out << " ) {";
        out.incrementIndent();
        out.endLine();

        for ( const auto& c : n.cases() ) {
            out.beginLine();

            if ( ! c.isDefault() )
                out << "case " << std::make_pair(c.expressions(), ", ") << ": ";
            else
                out << "default: ";

            out << c.body();
            out.endLine();
        }

        out.decrementIndent();
        out.beginLine();
        out << "}";
        out.endLine();
    }

    void operator()(const statement::Throw& n) {
        out.beginLine();
        out << "throw";

        if ( auto e = n.expression() )
            out << fmt(" %s", *e);

        out << ";";
        out.endLine();
    }

    void operator()(const statement::try_::Catch& n) {
        out.beginLine();
        out << "catch ";

        if ( auto p = n.parameter() )
            out << "( " << Declaration(*p) << " ) ";

        out << n.body();
    }

    void operator()(const statement::Try& n) {
        out.beginLine();
        out << "try " << n.body();

        for ( const auto& c : n.catches() )
            out << c;

        out.endLine();
    }

    void operator()(const statement::While& n) {
        out.emptyLine();
        out.beginLine();
        out << "while ( ";

        if ( auto e = n.init() )
            out << *e << "; ";

        if ( auto e = n.condition() )
            out << *e;

        out << " ) " << n.body();

        if ( n.else_() ) {
            out.beginLine();
            out << "else " << *n.else_();
        }

        out.endLine();
    }

    void operator()(const statement::Yield& n) {
        out.beginLine();
        out << "yield";
        out.endLine();
    }

    void operator()(const expression::ResolvedOperator& n) {
        out << renderOperator(n.operator_().kind(), node::transform(n.operands(), [](auto o) { return fmt("%s", o); }));
    }

    void operator()(const expression::UnresolvedOperator& n) {
        out << renderOperator(n.kind(), node::transform(n.operands(), [](auto o) { return fmt("%s", o); }));
    }

    ////// Types

    void operator()(const type::Any& n) { out << const_(n) << "any"; }

    void operator()(const type::Address& n) { out << const_(n) << "addr"; }

    void operator()(const type::Auto& n) { out << const_(n) << "auto"; }

    void operator()(const type::Bool& n) { out << const_(n) << "bool"; }

    void operator()(const type::Bytes& n) { out << const_(n) << "bytes"; }

    void operator()(const type::enum_::Label& n) { out << n.id() << " = " << n.value(); }

    void operator()(const type::Enum& n, position_t p) {
        if ( ! out.isExpandSubsequentType() ) {
            out.setExpandSubsequentType(false);
            if ( auto id = p.node.as<Type>().typeID() ) {
                out << *id;
                return;
            }
        }

        out.setExpandSubsequentType(false);

        auto x = util::transform(util::filter(n.labels(), [](const auto& l) { return l.get().id() != ID("Undef"); }),
                                 [](const auto& l) { return l.get(); });

        out << const_(n) << "enum { " << std::make_pair(std::move(x), ", ") << " }";
    }

    void operator()(const type::Error& n) { out << const_(n) << "error"; }

    void operator()(const type::Exception& n) {
        out << const_(n) << "exception";

        if ( auto t = n.baseType() ) {
            out << " : ";
            if ( auto id = t->typeID() )
                out << *id;
            else
                out << *t;
        }
    }

    void operator()(const type::Function& n) {
        out << const_(n) << "function ";
        printFunctionType(n, {});
    }

    void operator()(const type::Interval& n) { out << const_(n) << "interval"; }

    void operator()(const type::Member& n) { out << const_(n) << n.id(); }

    void operator()(const type::Network& n) { out << const_(n) << "net"; }

    void operator()(const type::Null& n) { out << const_(n) << "<null type>"; }

    void operator()(const type::OperandList& n) { out << const_(n) << "<operand list>"; }

    void operator()(const type::Optional& n) {
        if ( n.isWildcard() )
            out << const_(n) << "optional<*>";
        else {
            out << const_(n) << "optional<" << n.dereferencedType() << ">";
        }
    }

    void operator()(const type::Port& n) { out << const_(n) << "port"; }

    void operator()(const type::Real& n) { out << const_(n) << "real"; }

    void operator()(const type::StrongReference& n) {
        if ( n.isWildcard() )
            out << const_(n) << "strong_ref<*>";
        else
            out << const_(n) << "strong_ref<" << n.dereferencedType() << ">";
    }

    void operator()(const type::Stream& n) { out << const_(n) << "stream"; }

    void operator()(const type::bytes::Iterator& n) { out << const_(n) << "iterator<bytes>"; }

    void operator()(const type::list::Iterator& n) {
        if ( n.isWildcard() )
            out << const_(n) << "iterator<list<*>>";
        else
            out << const_(n) << fmt("iterator<list<%s>>", n.dereferencedType());
    }

    void operator()(const type::stream::Iterator& n) { out << const_(n) << "iterator<stream>"; }

    void operator()(const type::vector::Iterator& n) {
        if ( n.isWildcard() )
            out << const_(n) << "iterator<vector<*>>";
        else
            out << const_(n) << fmt("iterator<vector<%s>>", n.dereferencedType());
    }

    void operator()(const type::stream::View& n) { out << const_(n) << "view<stream>"; }

    void operator()(const type::Library& n, position_t p) {
        if ( auto id = p.node.as<Type>().typeID() )
            out << const_(n) << *id;
        else
            out << const_(n) << fmt("__library_type(\"%s\")", n.cxxName());
    }

    void operator()(const type::List& n) {
        if ( n.isWildcard() )
            out << const_(n) << "list<*>";
        else {
            out << const_(n) << "list<" << n.elementType() << ">";
        }
    }

    void operator()(const type::map::Iterator& n) {
        if ( n.isWildcard() )
            out << const_(n) << "iterator<map<*>>";
        else
            out << const_(n) << fmt("iterator<map<%s>>", n.dereferencedType());
    }

    void operator()(const type::Map& n) {
        if ( n.isWildcard() )
            out << const_(n) << "map<*>";
        else {
            out << const_(n) << "map<" << n.keyType() << ", " << n.valueType() << ">";
        }
    }

    void operator()(const type::RegExp& n) { out << const_(n) << "regexp"; }

    void operator()(const type::Result& n) {
        if ( n.isWildcard() )
            out << const_(n) << "result<*>";
        else {
            out << const_(n) << "result<" << n.dereferencedType() << ">";
        }
    }

    void operator()(const type::set::Iterator& n) {
        if ( n.isWildcard() )
            out << const_(n) << "iterator<set<*>>";
        else
            out << const_(n) << fmt("iterator<set<%s>>", n.dereferencedType());
    }

    void operator()(const type::Set& n) {
        if ( n.isWildcard() )
            out << const_(n) << "set<*>";
        else {
            out << const_(n) << "set<" << n.elementType() << ">";
        }
    }

    void operator()(const type::SignedInteger& n) {
        if ( n.isWildcard() )
            out << const_(n) << "int<*>";
        else
            out << const_(n) << fmt("int<%d>", n.width());
    }

    void operator()(const type::String& n) { out << const_(n) << "string"; }

    void operator()(const type::Struct& n, position_t p) {
        if ( ! out.isExpandSubsequentType() ) {
            if ( auto id = p.node.as<Type>().typeID() ) {
                out << *id;

                if ( n.parameters().size() )
                    out << '(' << std::make_pair(n.parameters(), ", ") << ')';

                return;
            }
        }

        out.setExpandSubsequentType(false);

        out << const_(n) << "struct";

        if ( n.parameters().size() )
            out << " (" << std::make_pair(n.parameters(), ", ") << ')';

        auto printFields = [&](const auto& fields) {
            for ( const auto& f : fields )
                out << Declaration(f);
        };

        out << " {" << out.newline();
        printFields(node::filter(n.fields(), [](const auto& f) { return ! f.type().template isA<type::Function>(); }));
        printFields(node::filter(n.fields(), [](const auto& f) { return f.type().template isA<type::Function>(); }));
        out << "}";
    }

    void operator()(const type::Time& n) { out << const_(n) << "time"; }

    void operator()(const type::Type_& n) { out << const_(n) << fmt("type<%s>", n.typeValue()); }

    void operator()(const type::Union& n, position_t p) {
        if ( ! out.isExpandSubsequentType() ) {
            if ( auto id = p.node.as<Type>().typeID() ) {
                out << *id;
                return;
            }
        }

        out.setExpandSubsequentType(false);

        out << const_(n) << "union {" << out.newline();

        for ( const auto& f : n.fields() )
            out << f;

        out << "}";
    }

    void operator()(const type::Unknown& n) { out << const_(n) << "<unknown type>"; }

    void operator()(const type::UnsignedInteger& n) {
        if ( n.isWildcard() )
            out << const_(n) << "uint<*>";
        else
            out << const_(n) << fmt("uint<%d>", n.width());
    }

    void operator()(const type::Tuple& n) {
        if ( n.isWildcard() )
            out << const_(n) << "tuple<*>";
        else {
            out << const_(n) << "tuple<";

            auto types = node::transform(n.elements(), [](const auto& x) {
                return x.id() ? fmt("%s: %s", *x.id(), x.type()) : fmt("%s", x.type());
            });

            out << util::join(types, ", ") << '>';
        }
    }

    void operator()(const type::UnresolvedID& n) { out << const_(n) << n.id(); }

    void operator()(const type::Vector& n) {
        if ( n.isWildcard() )
            out << const_(n) << "vector<*>";
        else {
            out << const_(n) << "vector<" << n.elementType() << ">";
        }
    }

    void operator()(const type::Void& n) { out << const_(n) << "void"; }

    void operator()(const type::WeakReference& n) {
        if ( n.isWildcard() )
            out << const_(n) << "weak_ref<*>";
        else
            out << const_(n) << "weak_ref<" << n.dereferencedType() << ">";
    }

    void operator()(const type::ValueReference& n) {
        if ( n.isWildcard() )
            out << const_(n) << "value_ref<*>";
        else
            out << const_(n) << "value_ref<" << n.dereferencedType() << ">";
    }

private:
    printer::Stream& out;
};

} // anonymous namespace

void hilti::detail::printAST(const Node& root, std::ostream& out, bool compact) {
    auto stream = printer::Stream(out, compact);
    printAST(root, stream);
}

void hilti::detail::printAST(const Node& root, printer::Stream& stream) {
    util::timing::Collector _("hilti/printer");

    if ( auto t = root.tryAs<Type>() ) {
        if ( ! stream.isExpandSubsequentType() ) {
            if ( auto id = t->typeID() ) {
                stream << *id;
                return;
            }
        }
    }

    for ( auto& p : plugin::registry().plugins() ) {
        if ( ! p.ast_print )
            continue;

        if ( (*p.ast_print)(root, stream) )
            return;
    }

    Visitor(stream).dispatch(root);
}

std::string hilti::detail::renderOperatorPrototype(const expression::ResolvedOperator& o) {
    const auto& op = o.operator_();
    const auto& exprs = o.operands();

    switch ( op.kind() ) {
        case operator_::Kind::Call: {
            assert(exprs.size() == 2);
            auto id = exprs[0];
            auto ops =
                operator_::type(o.operator_().operands()[1].type, exprs, exprs)->as<type::OperandList>().operands();
            auto args =
                util::join(util::transform(ops, [&](auto x) { return fmt("<%s>", renderOperand(x, exprs)); }), ", ");
            return fmt("%s(%s)", id, args);
        }

        case operator_::Kind::MemberCall: {
            assert(exprs.size() == 3);
            auto self = exprs[0];
            auto id = exprs[1];
            auto ops =
                operator_::type(o.operator_().operands()[2].type, exprs, exprs)->as<type::OperandList>().operands();
            auto args =
                util::join(util::transform(ops, [&](auto x) { return fmt("<%s>", renderOperand(x, exprs)); }), ", ");
            return fmt("<%s>.%s(%s)", renderExpressionType(self), id, args);
        }

        default:
            return renderOperator(op.kind(), util::transform(op.operands(), [&](auto x) {
                                      return fmt("<%s>", renderOperand(x, exprs));
                                  }));
    }
}

static std::string _renderOperatorInstance(operator_::Kind kind, const node::Range<Expression>& exprs) {
    switch ( kind ) {
        case operator_::Kind::Call: {
            assert(exprs.size() == 2);
            const auto& id = exprs[0];
            auto ops = exprs[1].as<expression::Ctor>().ctor().as<ctor::Tuple>().value();
            auto args =
                util::join(node::transform(ops, [&](auto x) { return fmt("<%s>", renderExpressionType(x)); }), ", ");
            return fmt("%s(%s)", id, args);
        }

        case operator_::Kind::MemberCall: {
            assert(exprs.size() == 3);
            const auto& self = exprs[0];
            const auto& id = exprs[1];
            auto ops = exprs[2].as<expression::Ctor>().ctor().as<ctor::Tuple>().value();
            auto args =
                util::join(node::transform(ops, [&](auto x) { return fmt("<%s>", renderExpressionType(x)); }), ", ");
            return fmt("<%s>.%s(%s)", renderExpressionType(self), id, args);
        }

        default:
            return renderOperator(kind,
                                  node::transform(exprs, [&](auto x) { return fmt("<%s>", renderExpressionType(x)); }));
    }
}

std::string hilti::detail::renderOperatorInstance(const expression::ResolvedOperator& o) {
    return _renderOperatorInstance(o.operator_().kind(), o.operands());
}

std::string hilti::detail::renderOperatorInstance(const expression::UnresolvedOperator& o) {
    return _renderOperatorInstance(o.kind(), o.operands());
}
