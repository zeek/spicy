// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <cstdio>
#include <ranges>

#include <hilti/ast/all.h>
#include <hilti/ast/function.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>
#include <hilti/compiler/plugin.h>
#include <hilti/compiler/printer.h>

using namespace hilti;
using util::fmt;

printer::Stream& printer::Stream::operator<<(const ID& id) {
    if ( const auto* plugin = state().current_plugin ) {
        if ( auto hook = plugin->ast_print_id; hook && hook(id, *this) )
            return *this; // plugin handled it
    }

    if ( id.namespace_() == currentScope() )
        (*this) << std::string(id.local());
    else
        (*this) << std::string(id);

    return *this;
}

namespace {

struct Printer : visitor::PreOrder {
    Printer(printer::Stream& out) : _out(out) {} // NOLINT

    void printFunctionType(const type::Function& ftype, const ID& id) {
        if ( ftype.isWildcard() ) {
            _out << "<function>";
            return;
        }

        _out << to_string(ftype.flavor()) << ' ';

        if ( ftype.flavor() == type::function::Flavor::Function ) {
            if ( ftype.callingConvention() != type::function::CallingConvention::Standard )
                _out << to_string(ftype.callingConvention()) << ' ';
        }

        _out << ftype.result() << ' ';

        if ( id )
            _out << id;

        _out << '(';
        _out << std::make_pair(ftype.parameters(), ", ");
        _out << ')';
    }

    void printDoc(const std::optional<DocString>& doc) {
        if ( doc && *doc ) {
            _out.emptyLine();
            doc->print(_out);
        }
    }

    auto linkage(declaration::Linkage l) {
        switch ( l ) {
            case declaration::Linkage::Init: return "init ";
            case declaration::Linkage::PreInit: return "preinit ";
            case declaration::Linkage::Public: return "public ";
            case declaration::Linkage::Struct: [[fallthrough]];
            case declaration::Linkage::Private: return ""; // That's the default.
            default: util::cannotBeReached();
        }
    }

    auto const_(const QualifiedType* t) {
        return (_out.isCompact() && t->isConstant() && t->type()->isMutable()) ? "const " : "";
    }

    auto kind(parameter::Kind k) {
        switch ( k ) {
            case parameter::Kind::Copy: return "copy ";
            case parameter::Kind::In: return "";
            case parameter::Kind::InOut: return "inout ";
            case parameter::Kind::Unknown: logger().internalError("parameter kind not set");
        }

        util::cannotBeReached();
    };

    void operator()(ASTRoot* n) final {
        // This implementation is for debugging only. User code shouldn't ever
        // be able print the whole AST, just individual modules.
        for ( const auto& m : n->children() ) {
            _out << m;
            _out << "===========================\n";
        }
    }

    void operator()(Attribute* n) final {
        _out << to_string(n->kind());

        if ( n->hasValue() )
            _out << "=" << n->value();
    }

    void operator()(AttributeSet* n) final {
        bool first = true;
        for ( const auto& a : n->attributes() ) {
            if ( ! first )
                _out << ' ';
            else
                first = false;

            _out << a;
        }
    }

    void operator()(Function* n) final {
        printFunctionType(*n->ftype(), n->id());

        if ( auto attrs = n->attributes()->attributes(); ! attrs.empty() )
            _out << ' ' << std::make_pair(attrs, " ");

        if ( n->body() )
            _out << ' ' << n->body();
        else
            _out << ';' << _out.newline();
    }

    void operator()(declaration::Module* n) final {
        printDoc(n->documentation());
        _out.beginLine();
        _out << "module " << n->scopeID() << " {" << _out.newline();
        _out.endLine();

        _out.pushScope(n->scopeID());


        auto print_decls = [&](auto&& decls) {
            bool empty = true;
            for ( const auto& d : decls ) {
                _out << d;
                empty = false;
            }

            if ( ! empty )
                _out.emptyLine();
        };


        print_decls(n->declarations() |
                    std::views::filter([](const auto& d) { return d->template isA<declaration::ImportedModule>(); }));
        print_decls(n->declarations() |
                    std::views::filter([](const auto& d) { return d->template isA<declaration::Type>(); }));
        print_decls(n->declarations() |
                    std::views::filter([](const auto& d) { return d->template isA<declaration::Constant>(); }));
        print_decls(n->declarations() |
                    std::views::filter([](const auto& d) { return d->template isA<declaration::GlobalVariable>(); }));
        print_decls(n->declarations() |
                    std::views::filter([](const auto& d) { return d->template isA<declaration::Function>(); }));

        for ( const auto& s : n->statements()->statements() )
            _out << s;

        if ( ! n->statements()->statements().empty() )
            _out.emptyLine();

        _out.popScope();

        _out.beginLine();
        _out << "}";
        _out.endLine();
    }

    ////// Ctors

    void operator()(ctor::Address* n) final { _out << n->value(); }

    void operator()(ctor::Bitfield* n) final {
        _out << "[";

        bool first = true;
        for ( const auto& f : n->bits() ) {
            if ( ! first )
                _out << ", ";
            else
                first = false;

            _out << '$' << f->id() << "=" << f->expression();
        }

        _out << "]";
    }

    void operator()(ctor::Bool* n) final { _out << (n->value() ? "True" : "False"); }

    void operator()(ctor::Bytes* n) final {
        _out << "b\"" << util::escapeBytes(n->value(), hilti::rt::render_style::Bytes::EscapeQuotes) << '"';
    }

    void operator()(ctor::Coerced* n) final { _out << n->originalCtor(); }

    void operator()(ctor::Default* n) final {
        _out << "default<" << n->type() << ">(" << std::make_pair(n->typeArguments(), ", ") << ")";
    }

    void operator()(ctor::Enum* n) final {
        if ( n->type()->type()->typeID() )
            _out << n->type()->type()->typeID() << "::" << n->value()->id();
        else
            _out << "<anon-enum>::" << n->value()->id();
    }

    void operator()(ctor::Error* n) final { _out << "error(\"" << n->value() << "\")"; }

    void operator()(ctor::Exception* n) final { _out << n->value(); }

    void operator()(ctor::Interval* n) final { _out << "interval_ns(" << n->value().nanoseconds() << ")"; }

    void operator()(ctor::List* n) final { _out << '[' << std::make_pair(n->value(), ", ") << ']'; }

    void operator()(ctor::Map* n) final {
        auto elems = node::transform(n->value(), [](const auto& e) -> std::string {
            return fmt("%s: %s", *e->key(), *e->value());
        });
        _out << "map(" << std::make_pair(elems, ", ") << ')';
    }

    void operator()(ctor::Network* n) final { _out << n->value(); }

    void operator()(ctor::Null* n) final { _out << "Null"; }

    void operator()(ctor::Optional* n) final {
        if ( n->value() )
            _out << "optional(" << n->value() << ")";
        else
            _out << "Null";
    }

    void operator()(ctor::Port* n) final { _out << n->value(); }

    void operator()(ctor::Real* n) final {
        // We use hexformat for lossless serialization-> Older platforms like
        // centos7 have inconsistent support for that in iostreams so we use
        // C99 snprintf instead.
        constexpr size_t size = 256;
        char buf[size];
        std::snprintf(buf, size, "%a", n->value());
        _out << buf;
    }

    void operator()(ctor::StrongReference* n) final { _out << "Null"; }

    void operator()(ctor::RegExp* n) final {
        _out << std::make_pair(n->patterns() | std::views::transform([](const auto& p) { return to_string(p); }),
                               " | ");

        if ( auto* attrs = n->attributes(); *attrs )
            _out << ' ' << std::make_pair(attrs->attributes(), " ");
    }

    void operator()(ctor::Result* n) final {
        if ( n->value() )
            _out << n->value();
        else
            _out << n->error();
    }

    void operator()(ctor::Set* n) final { _out << "set(" << std::make_pair(n->value(), ", ") << ')'; }

    void operator()(ctor::SignedInteger* n) final {
        if ( n->width() < 64 )
            _out << fmt("int%d(%" PRId64 ")", n->width(), n->value());
        else
            _out << n->value();
    }

    void operator()(ctor::Stream* n) final {
        _out << "stream(" << util::escapeUTF8(n->value(), hilti::rt::render_style::UTF8::EscapeQuotes) << ')';
    }

    void operator()(ctor::String* n) final {
        _out << '"' << util::escapeUTF8(n->value(), hilti::rt::render_style::UTF8::EscapeQuotes) << '"';
    }

    void operator()(ctor::Struct* n) final {
        _out << "[";

        bool first = true;
        for ( const auto& f : n->fields() ) {
            if ( ! first )
                _out << ", ";
            else
                first = false;

            _out << '$' << f->id() << "=" << f->expression();
        }

        _out << "]";
    }

    void operator()(ctor::Time* n) final { _out << "time_ns(" << n->value().nanoseconds() << ")"; }

    void operator()(ctor::Tuple* n) final { _out << '(' << std::make_pair(n->value(), ", ") << ')'; }

    void operator()(ctor::UnsignedInteger* n) final {
        if ( n->width() < 64 )
            _out << fmt("uint%d(%" PRId64 ")", n->width(), n->value());
        else
            _out << n->value();
    }

    void operator()(ctor::Vector* n) final { _out << "vector(" << std::make_pair(n->value(), ", ") << ')'; }

    void operator()(ctor::WeakReference* n) final { _out << "Null"; }

    void operator()(ctor::ValueReference* n) final { _out << n->expression(); }

    ////// Declarations

    void operator()(declaration::Constant* n) final {
        printDoc(n->documentation());
        _out.beginLine();
        _out << linkage(n->linkage()) << "const ";
        _out << n->type();
        _out << ' ' << n->id() << " = " << n->value() << ';';
        _out.endLine();
    }

    void operator()(declaration::Expression* n) final { _out << n->expression(); }

    void operator()(declaration::Field* n) final {
        _out << "    ";

        if ( auto* ft = n->type()->type()->tryAs<type::Function>() ) {
            _out << to_string(ft->flavor()) << " ";

            if ( ft->flavor() == type::function::Flavor::Function ) {
                if ( auto cc = ft->callingConvention(); cc != type::function::CallingConvention::Standard )
                    _out << to_string(cc) << ' ';
            }

            _out << ft->result() << " " << n->id() << "(" << std::make_pair(ft->parameters(), ", ") << ")";
        }

        else
            _out << n->type() << ' ' << n->id();

        if ( auto* attrs = n->attributes(); ! attrs->attributes().empty() )
            _out << ' ' << attrs;

        if ( auto* f = n->inlineFunction(); f && f->body() ) {
            const auto& block = f->body()->tryAs<statement::Block>();
            if ( block && block->statements().empty() ) {
                _out << " {}";
                _out.endLine();
            }
            else if ( block && block->statements().size() == 1 ) {
                _out << " { " << *block->statements().begin() << " }";
                _out.endLine();
            }
            else {
                _out.incrementIndent();
                _out << ' ' << f->body();
                _out.decrementIndent();
            }
        }
        else
            _out << ";" << _out.newline();
    }

    void operator()(declaration::Parameter* n) final {
        _out << kind(n->kind()) << n->type()->type() << ' ' << n->id();

        if ( n->default_() )
            _out << " = " << n->default_();

        if ( auto* attrs = n->attributes(); ! attrs->attributes().empty() )
            _out << ' ' << attrs;
    }

    void operator()(declaration::Function* n) final {
        const auto& func = n->function();

        if ( ! func->body() ) {
            printDoc(n->documentation());
            _out.beginLine();
            _out << "declare ";
        }
        else {
            _out.emptyLine();
            printDoc(n->documentation());
            _out.beginLine();
        }

        _out << linkage(n->linkage());
        _out << n->function();
    }

    void operator()(declaration::ImportedModule* n) final {
        _out.beginLine();
        if ( n->scope() )
            _out << "import " << n->id() << " from " << n->scope() << ';';
        else
            _out << "import " << n->id() << ';';

        _out.endLine();
    }

    void operator()(declaration::Type* n) final {
        printDoc(n->documentation());
        _out.beginLine();
        for ( const auto& comment : n->meta().comments() )
            _out << "# " << comment << '\n';
        _out << linkage(n->linkage()) << "type " << n->id() << " = ";
        _out.setExpandSubsequentType(true);
        _out << n->type();

        if ( auto* attrs = n->attributes(); ! attrs->attributes().empty() )
            _out << ' ' << attrs;

        _out << ';';
        _out.endLine();
    }

    void operator()(declaration::LocalVariable* n) final {
        // Will be printed through a statement, hence no outer formatting.
        _out << "local ";

        if ( n->type() )
            _out << n->type() << ' ';

        _out << n->id();

        if ( n->typeArguments().size() )
            _out << '(' << std::make_pair(n->typeArguments(), ", ") << ')';

        // We use void expressions as a hint for the initialization mechanism
        // to use in C++ codegen. These expressions have no actual equivalent
        // in the syntax.
        //
        // To still somehow capture them in HILTI output render them by
        // declaring a variable with no constructor arguments; this is distinct
        // from HILTI default initialization which uses assignment syntax. This
        // is not 100% equivalent, but allows rendering valid code.
        if ( auto* init = n->init() ) {
            if ( init->isA<expression::Void>() )
                _out << "()";
            else
                _out << " = " << init;
        }
    }

    void operator()(declaration::GlobalVariable* n) final {
        printDoc(n->documentation());
        _out.beginLine();
        _out << linkage(n->linkage()) << "global ";

        if ( n->type() )
            _out << n->type() << ' ';

        _out << n->id();

        if ( n->typeArguments().size() )
            _out << '(' << std::make_pair(n->typeArguments(), ", ") << ')';

        if ( n->init() )
            _out << " = " << n->init();

        _out << ';';
        _out.endLine();
    }

    ////// Expressions

    void operator()(expression::Assign* n) final { _out << n->target() << " = " << n->source(); }

    void operator()(expression::BuiltInFunction* n) final {
        _out << n->name() << "("
             << util::join(node::transform(n->arguments(), [](auto p) { return fmt("%s", p); }), ", ") << ")";
    }

    void operator()(expression::Coerced* n) final { _out << n->expression(); }

    void operator()(expression::Ctor* n) final { _out << n->ctor(); }

    void operator()(expression::Grouping* n) final { _out << '(' << n->expression() << ')'; }

    void operator()(expression::Keyword* n) final {
        switch ( n->kind() ) {
            case expression::keyword::Kind::Self: _out << "self"; break;
            case expression::keyword::Kind::DollarDollar: _out << "$$"; break;
            case expression::keyword::Kind::Captures:
                _out << "$@"; // this is technically not valid source code; we don't expose this to users
                break;
            case expression::keyword::Kind::Scope: _out << "$scope"; break;
        }
    }

    void operator()(expression::ListComprehension* n) final {
        _out << '[' << n->output() << " for " << n->local()->id() << " in " << n->input();

        if ( n->condition() )
            _out << " if " << n->condition();

        _out << ']';
    }

    void operator()(expression::LogicalAnd* n) final { _out << n->op0() << " && " << n->op1(); }

    void operator()(expression::LogicalNot* n) final { _out << "! " << n->expression(); }

    void operator()(expression::LogicalOr* n) final { _out << n->op0() << " || " << n->op1(); }

    void operator()(expression::Member* n) final { _out << n->id(); }

    void operator()(expression::Move* n) final { _out << "move(" << n->expression() << ")"; }

    void operator()(expression::Name* n) final { _out << n->id(); }

    void operator()(expression::ConditionTest* n) final { _out << n->condition() << " : " << n->error(); }

    void operator()(expression::ResolvedOperator* n) final {
        _out << operator_::detail::print(n->kind(), n->operands());
    }

    void operator()(expression::UnresolvedOperator* n) final {
        _out << operator_::detail::print(n->kind(), n->operands());
    }

    void operator()(expression::Ternary* n) final {
        _out << n->condition() << " ? " << n->true_() << " : " << n->false_();
    }

    void operator()(expression::Type_* n) final {
        if ( auto id = n->typeValue()->type()->typeID() )
            _out << id;
        else
            _out << n->typeValue();
    }

    void operator()(expression::TypeInfo* n) final { _out << "typeinfo(" << n->expression() << ")"; }

    void operator()(expression::TypeWrapped* n) final { _out << n->expression(); }

    void operator()(expression::Void* n) final {
        _out << "<void expression>"; // Shouldn't really happen->
    }

    ////// Statements

    void operator()(statement::Assert* n) final {
        _out.beginLine();

        if ( n->expectException() )
            _out << "assert-exception ";
        else
            _out << "assert ";

        _out << n->expression();
        if ( n->message() )
            _out << " : " << n->message();
        _out << ";";
        _out.endLine();
    }

    void operator()(statement::Block* n) final {
        if ( _out.indent() == 0 || n->statements().size() != 1 )
            _out << "{";

        _out.endLine();
        _out.incrementIndent();

        const auto& stmts = n->statements();
        for ( const auto&& [i, s] : util::enumerate(stmts) ) {
            _out.setPositionInBlock(i == 0, i == (stmts.size() - 1));

            if ( s->isA<statement::Block>() )
                _out.beginLine();

            _out << s;

            if ( s->isA<statement::Block>() )
                _out.endLine();
        }

        _out.decrementIndent();

        if ( _out.indent() == 0 || n->statements().size() != 1 ) {
            _out.beginLine();
            _out << "}";
            _out.endLine();
        }
    }

    void operator()(statement::Break* n) final {
        _out.beginLine();
        _out << "break;";
        _out.endLine();
    }

    void operator()(statement::Continue* n) final {
        _out.beginLine();
        _out << "continue;";
        _out.endLine();
    }

    void operator()(statement::Comment* n) final {
        if ( (n->separator() == hilti::statement::comment::Separator::Before ||
              n->separator() == hilti::statement::comment::Separator::BeforeAndAfter) &&
             ! _out.isFirstInBlock() )
            _out.emptyLine();

        _out.beginLine();
        _out << "# " << n->comment();
        _out.endLine();

        if ( (n->separator() == hilti::statement::comment::Separator::After ||
              n->separator() == hilti::statement::comment::Separator::BeforeAndAfter) &&
             ! _out.isLastInBlock() )
            _out.emptyLine();
    }

    void operator()(statement::Declaration* n) final {
        _out.beginLine();
        _out << n->declaration() << ';';
        _out.endLine();
    }

    void operator()(statement::Expression* n) final {
        _out.beginLine();
        _out << n->expression() << ';';
        _out.endLine();
    }

    void operator()(statement::For* n) final {
        _out.emptyLine();
        _out.beginLine();
        _out << "for ( " << n->local()->id() << " in " << n->sequence() << " ) " << n->body();
        _out.endLine();
    }

    void operator()(statement::If* n) final {
        _out.emptyLine();
        _out.beginLine();
        _out << "if ( ";

        if ( auto* e = n->init() )
            _out << e << "; ";

        if ( auto* e = n->condition() )
            _out << e;

        _out << " ) " << n->true_();

        if ( n->false_() ) {
            _out.beginLine();
            _out << "else " << n->false_();
        }

        _out.endLine();
    }

    void operator()(statement::SetLocation* n) final {
        _out.beginLine();
        _out << "# " << n->expression();
        _out.endLine();
    }

    void operator()(statement::Return* n) final {
        _out.beginLine();
        _out << "return";

        if ( auto* e = n->expression() )
            _out << ' ' << e;

        _out << ';';
        _out.endLine();
    }

    void operator()(statement::Switch* n) final {
        _out.emptyLine();
        _out.beginLine();
        _out << "switch ( ";

        if ( const auto& cond = n->condition(); cond->id().str() != "__x" )
            _out << cond;
        else
            _out << cond->init();

        _out << " ) {";
        _out.incrementIndent();
        _out.endLine();

        for ( const auto& c : n->cases() ) {
            _out.beginLine();

            if ( ! c->isDefault() )
                _out << "case " << std::make_pair(c->expressions(), ", ") << ": ";
            else
                _out << "default: ";

            _out << c->body();
            _out.endLine();
        }

        _out.decrementIndent();
        _out.beginLine();
        _out << "}";
        _out.endLine();
    }

    void operator()(statement::Throw* n) final {
        _out.beginLine();
        _out << "throw";

        if ( auto* e = n->expression() )
            _out << fmt(" %s", *e);

        _out << ";";
        _out.endLine();
    }

    void operator()(statement::try_::Catch* n) final {
        _out.beginLine();
        _out << "catch ";

        if ( auto* p = n->parameter() )
            _out << "( " << p << " ) ";

        _out << n->body();
    }

    void operator()(statement::Try* n) final {
        _out.beginLine();
        _out << "try " << n->body();

        for ( const auto& c : n->catches() )
            _out << c;

        _out.endLine();
    }

    void operator()(statement::While* n) final {
        _out.emptyLine();
        _out.beginLine();
        _out << "while ( ";

        if ( auto* e = n->init() )
            _out << e << "; ";

        if ( auto* e = n->condition() )
            _out << e;

        _out << " ) " << n->body();

        if ( n->else_() ) {
            _out.beginLine();
            _out << "else " << n->else_();
        }

        _out.endLine();
    }

    void operator()(statement::Yield* n) final {
        _out.beginLine();
        _out << "yield";
        _out.endLine();
    }

    ////// Types

    void operator()(QualifiedType* n) final { _out << const_(n) << n->type(false); }

    void operator()(type::Any* n) final { _out << "any"; }

    void operator()(type::Address* n) final { _out << "addr"; }

    void operator()(type::Auto* n) final { _out << "auto"; }

    void operator()(type::bitfield::BitRange* n) final {
        _out << "    " << n->id() << ": ";

        if ( n->lower() == n->upper() )
            _out << fmt("%d", n->lower());
        else
            _out << fmt("%d..%d", n->lower(), n->upper());

        if ( auto* attrs = n->attributes(); ! attrs->attributes().empty() )
            _out << ' ' << attrs;

        _out << ";" << _out.newline();
    }

    void operator()(type::Bitfield* n) final {
        if ( ! _out.isExpandSubsequentType() ) {
            if ( auto id = n->typeID() ) {
                _out << id;
                return;
            }
        }

        _out.setExpandSubsequentType(false);

        _out << fmt("bitfield(%d) {", n->width()) << _out.newline();

        for ( const auto& f : n->bits() )
            _out << f;

        _out << "}";
    }

    void operator()(type::Bool* n) final { _out << "bool"; }

    void operator()(type::Bytes* n) final { _out << "bytes"; }

    void operator()(type::enum_::Label* n) final { _out << n->id() << " = " << n->value(); }

    void operator()(type::Enum* n) final {
        if ( ! _out.isExpandSubsequentType() ) {
            _out.setExpandSubsequentType(false);
            if ( auto id = n->typeID() ) {
                _out << id;
                return;
            }
        }

        _out.setExpandSubsequentType(false);

        auto x = n->labels() | std::views::filter([](auto l) { return l->id() != ID("Undef"); }) |
                 std::views::transform([](const auto& l) { return l->print(); });

        _out << "enum { " << std::make_pair(util::toVector(std::move(x)), ", ") << " }";
    }

    void operator()(type::Error* n) final { _out << "error"; }

    void operator()(type::Exception* n) final {
        if ( ! _out.isExpandSubsequentType() ) {
            _out.setExpandSubsequentType(false);
            if ( auto id = n->typeID() ) {
                _out << id;
                return;
            }
        }

        _out.setExpandSubsequentType(false);

        if ( auto* t = n->baseType(); t && ! t->isA<type::Unknown>() ) {
            _out << "[exception :";

            if ( auto id = t->typeID() )
                _out << id;
            else
                _out << t;
        }
        else
            _out << "exception";
    }

    void operator()(type::Function* n) final {
        _out << "function ";
        printFunctionType(*n, {});
    }

    void operator()(type::Interval* n) final { _out << "interval"; }

    void operator()(type::Member* n) final { _out << n->id(); }

    void operator()(type::Name* n) final { _out << n->id(); }

    void operator()(type::Network* n) final { _out << "net"; }

    void operator()(type::Null* n) final { _out << "<null type>"; }

    void operator()(type::OperandList* n) final { _out << "(" << std::make_pair(n->operands(), ", ") << ")"; }

    void operator()(type::operand_list::Operand* n) final {
        if ( n->isOptional() )
            _out << "[";

        _out << kind(n->kind());

        if ( n->id() )
            _out << fmt("%s: ", n->id());

        _out << n->type()->type();

        if ( n->default_() )
            _out << fmt(" = %s", *n->default_());

        if ( n->isOptional() )
            _out << "]";
    }

    void operator()(type::Optional* n) final {
        if ( n->isWildcard() )
            _out << "optional<*>";
        else {
            _out << "optional<" << n->dereferencedType() << ">";
        }
    }

    void operator()(type::Port* n) final { _out << "port"; }

    void operator()(type::Real* n) final { _out << "real"; }

    void operator()(type::StrongReference* n) final {
        if ( n->isWildcard() )
            _out << "strong_ref<*>";
        else
            _out << "strong_ref<" << n->dereferencedType() << ">";
    }

    void operator()(type::Stream* n) final { _out << "stream"; }

    void operator()(type::bytes::Iterator* n) final { _out << "iterator<bytes>"; }

    void operator()(type::list::Iterator* n) final {
        if ( n->isWildcard() )
            _out << "iterator<list<*>>";
        else
            _out << fmt("iterator<list<%s>>", *n->dereferencedType());
    }

    void operator()(type::stream::Iterator* n) final { _out << "iterator<stream>"; }

    void operator()(type::vector::Iterator* n) final {
        if ( n->isWildcard() )
            _out << "iterator<vector<*>>";
        else
            _out << fmt("iterator<vector<%s>>", *n->dereferencedType());
    }

    void operator()(type::stream::View* n) final { _out << "view<stream>"; }

    void operator()(type::Library* n) final {
        if ( auto id = n->typeID() )
            _out << id;
        else
            _out << fmt("__library_type(\"%s\")", n->cxxName());
    }

    void operator()(type::List* n) final {
        if ( n->isWildcard() )
            _out << "list<*>";
        else {
            _out << "list<" << n->elementType() << ">";
        }
    }

    void operator()(type::map::Iterator* n) final {
        if ( n->isWildcard() )
            _out << "iterator<map<*>>";
        else
            _out << fmt("iterator<map<%s>>", *n->dereferencedType());
    }

    void operator()(type::Map* n) final {
        if ( n->isWildcard() )
            _out << "map<*>";
        else {
            _out << "map<" << n->keyType() << ", " << n->valueType() << ">";
        }
    }

    void operator()(type::RegExp* n) final { _out << "regexp"; }

    void operator()(type::Result* n) final {
        if ( n->isWildcard() )
            _out << "result<*>";
        else {
            _out << "result<" << n->dereferencedType() << ">";
        }
    }

    void operator()(type::set::Iterator* n) final {
        if ( n->isWildcard() )
            _out << "iterator<set<*>>";
        else
            _out << fmt("iterator<set<%s>>", *n->dereferencedType());
    }

    void operator()(type::Set* n) final {
        if ( n->isWildcard() )
            _out << "set<*>";
        else {
            _out << "set<" << n->elementType() << ">";
        }
    }

    void operator()(type::SignedInteger* n) final {
        if ( n->isWildcard() )
            _out << "int<*>";
        else
            _out << fmt("int<%d>", n->width());
    }

    void operator()(type::String* n) final { _out << "string"; }

    void operator()(type::Struct* n) final {
        if ( ! _out.isExpandSubsequentType() ) {
            if ( auto id = n->typeID() ) {
                _out << id;

                if ( n->parameters().size() )
                    _out << '(' << std::make_pair(n->parameters(), ", ") << ')';

                return;
            }
        }

        _out.setExpandSubsequentType(false);

        _out << "struct";

        if ( n->parameters().size() )
            _out << " (" << std::make_pair(n->parameters(), ", ") << ')';

        auto print_fields = [&](auto&& fields) {
            for ( const auto& f : fields )
                _out << f;
        };

        _out << " {" << _out.newline();
        print_fields(n->fields() | std::views::filter([](const auto& f) {
                         return ! f->type()->type()->template isA<type::Function>();
                     }));
        print_fields(n->fields() | std::views::filter([](const auto& f) {
                         return f->type()->type()->template isA<type::Function>();
                     }));
        _out << "}";
    }

    void operator()(type::Time* n) final { _out << "time"; }

    void operator()(type::Type_* n) final {
        if ( n->isWildcard() )
            _out << "type<*>";
        else
            _out << fmt("%s", *n->typeValue());
    }

    void operator()(type::Union* n) final {
        if ( ! _out.isExpandSubsequentType() ) {
            if ( auto id = n->typeID() ) {
                _out << id;
                return;
            }
        }

        _out.setExpandSubsequentType(false);

        _out << "union {" << _out.newline();

        for ( const auto& f : n->fields() )
            _out << f;

        _out << "}";
    }

    void operator()(type::Unknown* n) final { _out << "<unknown type>"; }

    void operator()(type::UnsignedInteger* n) final {
        if ( n->isWildcard() )
            _out << "uint<*>";
        else
            _out << fmt("uint<%d>", n->width());
    }

    void operator()(type::Tuple* n) final {
        if ( n->isWildcard() )
            _out << "tuple<*>";
        else {
            _out << "tuple<";
            _out << std::make_pair(n->elements(), ", ");
            _out << '>';
        }
    }

    void operator()(type::tuple::Element* n) final {
        if ( n->id() )
            _out << fmt("%s: %s", n->id(), *n->type());
        else
            _out << fmt("%s", *n->type());
    }

    void operator()(type::Vector* n) final {
        if ( n->isWildcard() )
            _out << "vector<*>";
        else {
            _out << "vector<" << n->elementType() << ">";
        }
    }

    void operator()(type::Void* n) final { _out << "void"; }

    void operator()(type::WeakReference* n) final {
        if ( n->isWildcard() )
            _out << "weak_ref<*>";
        else
            _out << "weak_ref<" << n->dereferencedType() << ">";
    }

    void operator()(type::ValueReference* n) final {
        if ( n->isWildcard() )
            _out << "value_ref<*>";
        else
            _out << "value_ref<" << n->dereferencedType() << ">";
    }

private:
    printer::Stream& _out;
};

} // anonymous namespace

void printer::print(std::ostream& out, Node* root, bool compact, bool user_visible) {
    if ( ! detail::State::current ) {
        detail::State::current = std::make_unique<detail::State>();
        detail::State::current->user_visible = user_visible;
    }

    ++detail::State::depth;

    auto _ = util::scope_exit([&]() {
        if ( --detail::State::depth == 0 )
            detail::State::current.reset();
    });

    if ( compact ) {
        std::stringstream buffer;
        auto stream = printer::Stream(buffer);
        stream.setCompact(true);
        stream._print(root);
        auto data = buffer.str();
        data = util::trim(data);
        data = util::replace(data, "\n", " ");
        // NOLINTNEXTLINE(modernize-use-ranges)
        data.erase(std::unique(data.begin(), data.end(), [](char a, char b) { return a == ' ' && b == ' '; }),
                   data.end());
        out << data;
    }
    else {
        auto stream = printer::Stream(out);
        stream._print(root);
    }
}

void printer::Stream::_print(Node* root) {
    util::timing::Collector _("hilti/printer");

    for ( const auto& p : plugin::registry().plugins() ) {
        if ( ! p.ast_print )
            continue;

        const auto* prev = std::exchange(detail::State::current->current_plugin, &p);
        auto _ = util::scope_exit([&]() { detail::State::current->current_plugin = prev; });

        if ( (*p.ast_print)(root, *this) )
            return;
        else {
            // If the print hook did not succeed defer to default printer.
            // This might still make use of the currently selected plugin.
            Printer(*this).dispatch(root);
            return;
        }
    }

    // Defer to the default printer with the current plugin (which might be
    // unset).
    Printer(*this).dispatch(root);
}
