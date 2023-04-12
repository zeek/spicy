// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/json.h>

#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/cxx/elements.h>
#include <hilti/compiler/detail/cxx/formatter.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::cxx::formatter;

using nlohmann::json;
using util::fmt;

namespace flags {
static const unsigned int BlockEos = (1U << 0U);           // Add an end-of-statement after block (i.e., ';').
static const unsigned int NoSeparator = (1U << 1U);        // Don't add a separator after block.
static const unsigned int AddSeparatorAfter = (1U << 2U);  // Force adding a separator after block.
static const unsigned int AddSeparatorBefore = (1U << 4U); // Force adding a separator before block.
} // namespace flags


std::string cxx::normalize_id(std::string id) {
    static const std::set<std::string> reserved = {
        "NULL",
        "_Alignas",
        "_Alignof",
        "_Atomic",
        "_Bool",
        "_Complex",
        "_Decimal128",
        "_Decimal32",
        "_Decimal64",
        "_Generic",
        "_Imaginary",
        "_Noreturn",
        "_Pragma",
        "_Static_assert",
        "_Thread_local",
        "alignas",
        "alignof",
        "and",
        "and_eq",
        "asm",
        "atomic_cancel",
        "atomic_commit",
        "atomic_noexcept",
        "auto",
        "bitand",
        "bitor",
        "bool",
        "break",
        "case",
        "catch",
        "char",
        "char16_t",
        "char32_t",
        "char8_t",
        "class",
        "co_await",
        "co_return",
        "co_yield",
        "compl",
        "concept",
        "const",
        "const_cast",
        "consteval",
        "constexpr",
        "constinit",
        "continue",
        "decltype",
        "default",
        "delete",
        "do",
        "double",
        "dynamic_cast",
        "else",
        "enum",
        "explicit",
        "export",
        "extern",
        "false",
        "float",
        "for",
        "fortran",
        "friend",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "mutable",
        "namespace",
        "new",
        "noexcept",
        "not",
        "not_eq",
        "nullptr",
        "operator",
        "or",
        "or_eq",
        "private",
        "protected",
        "public",
        "reflexpr",
        "register",
        "reinterpret_cast",
        "requires",
        "restrict",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "static_assert",
        "static_cast",
        "struct",
        "switch",
        "synchronized",
        "template",
        "this",
        "thread_local",
        "true",
        "typedef",
        "typeid",
        "typename",
        "union",
        "unsigned",
        "using",
        "virtual",
        "void",
        "volatile",
        "wchar_t",
        "while",
        "xor",
        "xor_eq",
    };

    auto map = [](auto id) {
        if ( reserved.find(id) != reserved.end() )
            id.append("_");

        id = util::replace(id, "%", "0x25");
        id = util::replace(id, "~", "_0x7e_"); // we expect to see this only at the beginning (for "~finally")
        return id;
    };

    return util::join(util::transform(util::split(std::move(id), "::"), map), "::");
}

cxx::Block::Block(std::vector<std::string> stmts) {
    _stmts.reserve(stmts.size());
    for ( auto& s : stmts )
        _stmts.emplace_back(std::move(s), Block(), 0);
}

void cxx::Block::addStatement(std::string stmt) { _stmts.emplace_back(std::move(stmt), Block(), 0); }

void cxx::Block::addStatementAtFront(std::string stmt) { _stmts.insert(_stmts.begin(), {std::move(stmt), Block(), 0}); }

void cxx::Block::addBlock(Block child) { _stmts.emplace_back("", std::move(child), 0); }

void cxx::Block::appendFromBlock(Block b) {
    _stmts.insert(_stmts.end(), b._stmts.begin(), b._stmts.end());
    _tmps.insert(_tmps.end(), b._tmps.begin(), b._tmps.end());
}

void cxx::Block::addComment(const std::string& stmt, bool sep_before, bool sep_after) {
    Flags f = 0;

    if ( sep_before )
        f |= flags::AddSeparatorBefore;

    if ( sep_after )
        f |= flags::AddSeparatorAfter;

    _stmts.emplace_back(fmt("// %s", stmt), Block(), f);
}

inline std::string fmtDeclaration(const cxx::ID& id, const cxx::Type& type, const std::vector<cxx::Expression>& args,
                                  std::string linkage = "", std::optional<cxx::Expression> init = {}) {
    std::string sinit;

    if ( init )
        sinit = fmt(" = %s", *init);

    if ( ! linkage.empty() )
        linkage = fmt("%s ", linkage);

    std::string sargs;
    if ( args.size() )
        sargs = fmt("(%s)", util::join(args, ", "));

    return fmt("%s%s %s%s%s", linkage, type, id, sargs, sinit);
}

void cxx::Block::addLocal(const declaration::Local& v) {
    auto d = fmtDeclaration(v.id, v.type, v.args, v.linkage, v.init);
    _stmts.emplace_back(std::move(d), Block(), 0);
}

void cxx::Block::addTmp(const declaration::Local& v) {
    auto d = fmtDeclaration(v.id, v.type, v.args, v.linkage, v.init);
    _tmps.emplace_back(std::move(d));
}

void cxx::Block::addReturn(const Expression& expr) { _stmts.emplace_back(fmt("return %s", expr), Block(), 0); }

void cxx::Block::addLambda(const std::string& name, const std::string& signature, cxx::Block body) {
    body.setEnsureBracesforBlock();
    _stmts.emplace_back(fmt("auto %s = %s ", name, signature), body, flags::BlockEos);
}

void cxx::Block::addIf(const Expression& cond, cxx::Block true_) {
    true_._ensure_braces_for_block = true;
    _stmts.emplace_back(fmt("if ( %s )", cond), true_, flags::AddSeparatorAfter);
}

void cxx::Block::addIf(const Expression& init, const Expression& cond, cxx::Block true_) {
    true_._ensure_braces_for_block = true;
    _stmts.emplace_back(fmt("if ( %s; %s )", init, cond), true_, flags::AddSeparatorAfter);
}

void cxx::Block::addIf(const Expression& cond, cxx::Block true_, cxx::Block false_) {
    true_._ensure_braces_for_block = true;
    false_._ensure_braces_for_block = true;
    _stmts.emplace_back(fmt("if ( %s )", cond), true_, flags::NoSeparator);
    _stmts.emplace_back("else", false_, flags::AddSeparatorAfter);
}

void cxx::Block::addIf(const Expression& init, const Expression& cond, cxx::Block true_, cxx::Block false_) {
    true_._ensure_braces_for_block = true;
    false_._ensure_braces_for_block = true;
    _stmts.emplace_back(fmt("if ( %s; %s )", init, cond), true_, flags::NoSeparator);
    _stmts.emplace_back("else", false_, flags::AddSeparatorAfter);
}

void cxx::Block::addElseIf(const Expression& cond, cxx::Block true_) {
    true_._ensure_braces_for_block = true;
    _stmts.emplace_back(fmt("else if ( %s )", cond), true_, flags::AddSeparatorAfter);
}

void cxx::Block::addElse(cxx::Block true_) {
    true_._ensure_braces_for_block = true;
    _stmts.emplace_back("else ", true_, flags::AddSeparatorAfter);
}

void cxx::Block::addWhile(const Expression& cond, const cxx::Block& body) {
    _stmts.emplace_back(fmt("while ( %s )", cond), body, flags::AddSeparatorAfter);
}

void cxx::Block::addFor(const Expression& init, const Expression& cond, const Expression& next,
                        const cxx::Block& body) {
    _stmts.emplace_back(fmt("for ( %s; %s; %s )", init, cond, next), body, flags::AddSeparatorAfter);
}

void cxx::Block::addForRange(bool const_, const ID& id, const Expression& seq, const cxx::Block& body) {
    auto c = (const_ ? "const " : "");
    _stmts.emplace_back(fmt("for ( %sauto& %s : %s )", c, id, seq), body, flags::AddSeparatorAfter);
}

#if 0
void cxx::Block::addForRange(const Expression& init, bool const_, const ID& id, const Expression& seq, cxx::Block body) {
    auto c = (const_ ? "const " : "");
    _stmts.emplace_back(fmt("for ( %s; %sauto& %s : %s )", init, c, id, seq), body, flags::AddSeparatorAfter);
}
#endif

void cxx::Block::addSwitch(const Expression& cond, const std::vector<std::pair<Expression, Block>>& cases_,
                           std::optional<Block> default_) {
    auto x = Block();

    for ( const auto& c : cases_ )
        x._stmts.emplace_back(fmt("case %s:", c.first), c.second, 0);

    if ( default_ )
        x._stmts.emplace_back("default:", *default_, 0);

    _stmts.emplace_back(fmt("switch ( %s )", cond), std::move(x), flags::AddSeparatorAfter);
}
void cxx::Block::addTry(Block body, std::vector<std::pair<declaration::Argument, Block>> catches) {
    body.setEnsureBracesforBlock();
    _stmts.emplace_back("try", std::move(body), flags::NoSeparator);

    for ( auto& [e, b] : catches ) {
        b.setEnsureBracesforBlock();
        auto arg = std::string(e.type);
        if ( e.id )
            arg = fmt("%s %s", arg, e.id);

        _stmts.emplace_back(fmt("catch ( %s )", arg), std::move(b),
                            (e == catches.back().first ? flags::AddSeparatorAfter : flags::NoSeparator));
    }
}

size_t cxx::Block::size(bool ignore_comments) const {
    size_t x = 0;
    for ( const auto& [s, b, f] : _stmts ) {
        if ( ignore_comments && util::startsWith(s, "//") )
            continue;

        x += 1;
        x += b.size();
    }

    return x;
}

std::string cxx::declaration::Function::prototype(bool qualify) const {
    std::string qualifier;

    if ( const_ )
        qualifier = " const";

    if ( result == "void" || result == "auto" )
        return fmt("%s %s(%s)%s", result, (qualify ? id : id.local()), util::join(args, ", "), qualifier);

    if ( result == "" )
        return fmt("%s(%s)%s", (qualify ? id : id.local()), util::join(args, ", "), qualifier);

    return fmt("auto %s(%s)%s -> %s", (qualify ? id : id.local()), util::join(args, ", "), qualifier, result);
}

std::string cxx::declaration::Function::parameters() const { return fmt("(%s)", util::join(args, ", ")); }

cxx::Block& cxx::Block::operator+=(const cxx::Block& other) {
    for ( const auto& s : other._stmts )
        _stmts.push_back(s);

    return *this;
}

std::string cxx::declaration::Local::str() const { return fmtDeclaration(id, type, args, linkage, init); }

std::string cxx::declaration::Global::str() const { return fmtDeclaration(id, type, args, linkage, init); }

std::string cxx::type::Struct::str() const {
    std::vector<std::string> visitor_calls;

    auto fmt_member = [&](const auto& f) {
        if ( auto x = std::get_if<declaration::Local>(&f) ) {
            if ( ! (x->isInternal() || x->linkage == "inline static") ) // Don't visit internal or static fields.
                visitor_calls.emplace_back(fmt("_(\"%s\", %s); ", x->id, x->id));

            // We default initialize any members here that don't have an
            // explicit "init" expression. Those that do will be initialized
            // through our constructors.
            cxx::Expression init = x->init ? "" : "{}";
            return fmt("%s%s;", fmtDeclaration(x->id, x->type, x->args, x->linkage, {}), init);
        }

        if ( auto x = std::get_if<declaration::Function>(&f) ) {
            std::string linkage;

            if ( x->linkage == "static" )
                linkage = "static ";

            if ( x->linkage == "inline" )
                linkage = "inline ";

            if ( x->inline_body ) {
                cxx::Formatter formatter;
                formatter.compact_block = (! x->inline_body || x->inline_body->size() <= 1);
                formatter.indent();
                formatter << (*x->inline_body);
                formatter.dedent();
                return fmt("%s%s %s", linkage, x->prototype(false), util::trim(formatter.str()));
            }

            return fmt("%s%s;", linkage, x->prototype(false));
        }

        throw std::bad_variant_access();
    };

    auto fmt_argument = [&](const auto& a) {
        // We default initialize any parameters here that don't have an
        // explicit "default" expression. Those that do will be initialized
        // through our constructors.
        cxx::Expression default_ = a.default_ ? "" : "{}";

        if ( a.internal_type )
            return fmt("%s %s%s;", a.internal_type, a.id, default_);
        else
            return fmt("%s %s%s;", a.type, a.id, default_);
    };

    std::vector<std::string> struct_fields;
    util::append(struct_fields, util::transform(members, fmt_member));
    util::append(struct_fields, util::transform(args, fmt_argument));

    if ( add_ctors ) {
        auto dctor = fmt("inline %s();", type_name);
        auto cctor = fmt("%s(const %s&) = default;", type_name, type_name);
        auto mctor = fmt("%s(%s&&) = default;", type_name, type_name);
        auto cassign = fmt("%s& operator=(const %s&) = default;", type_name, type_name);
        auto massign = fmt("%s& operator=(%s&&) = default;", type_name, type_name);

        for ( const auto& x : {dctor, cctor, mctor, cassign, massign} )
            struct_fields.emplace_back(x);

        auto locals_user = util::filter(members, [](const auto& m) {
            auto l = std::get_if<declaration::Local>(&m);
            return l && ! l->isInternal();
        });

        if ( locals_user.size() ) {
            auto locals_ctor_args = util::join(util::transform(locals_user,
                                                               [&](const auto& x) {
                                                                   auto& l = std::get<declaration::Local>(x);
                                                                   return fmt("std::optional<%s> %s", l.type, l.id);
                                                               }),
                                               ", ");
            auto locals_ctor = fmt("inline %s(%s);", type_name, locals_ctor_args);
            struct_fields.emplace_back(std::move(locals_ctor));
        }

        if ( args.size() ) {
            // Add dedicated constructor to initialize the struct's arguments.
            auto params_ctor_args =
                util::join(util::transform(args, [&](const auto& x) { return fmt("%s %s", x.type, x.id); }), ", ");
            auto params_ctor = fmt("inline %s(%s);", type_name, params_ctor_args);
            struct_fields.emplace_back(params_ctor);
        }
    }

    struct_fields.emplace_back(
        fmt("template<typename F> void __visit(F _) const { %s}", util::join(visitor_calls, "")));
    auto struct_fields_as_str =
        util::join(util::transform(struct_fields, [&](const auto& x) { return fmt("    %s", x); }), "\n");

    std::string has_params;
    if ( args.size() )
        has_params = ", hilti::rt::trait::hasParameters";

    return fmt("struct %s : ::hilti::rt::trait::isStruct%s, ::hilti::rt::Controllable<%s> {\n%s\n}", type_name,
               has_params, type_name, struct_fields_as_str);
}

std::string cxx::type::Struct::inlineCode() const {
    if ( ! add_ctors )
        return "";

    auto locals_user = util::filter(members, [](const auto& m) {
        auto l = std::get_if<declaration::Local>(&m);
        return l && ! l->isInternal();
    });

    auto locals_non_user = util::filter(members, [](const auto& m) {
        auto l = std::get_if<declaration::Local>(&m);
        return l && l->isInternal();
    });

    auto init_locals_user = [&]() {
        return util::join(util::transform(locals_user,
                                          [&](const auto& x) {
                                              auto& l = std::get<declaration::Local>(x);
                                              return l.init ? fmt("    %s = %s;\n", l.id, *l.init) : std::string();
                                          }),
                          "");
    };

    auto init_locals_non_user = [&]() {
        return util::join(util::transform(locals_non_user,
                                          [&](const auto& x) {
                                              auto& l = std::get<declaration::Local>(x);
                                              return l.init ? fmt("    %s = %s;\n", l.id, *l.init) : std::string();
                                          }),
                          "");
    };

    auto init_parameters = [&]() {
        return util::join(util::transform(args,
                                          [&](const auto& x) {
                                              return x.default_ ? fmt("    %s = %s;\n", x.id, *x.default_) :
                                                                  std::string();
                                          }),
                          "");
    };

    std::string inline_code;

    // Create default constructor. This initializes user-controlled members
    // only if there are no struct parameters. If there are, we wouldn't have
    // access to them here yet and hence some init expressions might not
    // evaluate. However, in that case we will run through the
    // parameter-based constructors normally anyways, so don't need this
    // here.
    if ( args.size() )
        inline_code +=
            fmt("inline %s::%s() {\n%s%s}\n\n", type_name, type_name, init_parameters(), init_locals_non_user());
    else
        inline_code += fmt("inline %s::%s() {\n%s%s%s}\n\n", type_name, type_name, init_parameters(),
                           init_locals_user(), init_locals_non_user());

    if ( args.size() ) {
        // Create constructor taking the struct's parameters.
        auto ctor_args =
            util::join(util::transform(args, [&](const auto& x) { return fmt("%s %s", x.type, x.id); }), ", ");

        auto ctor_inits =
            util::join(util::transform(args, [&](const auto& x) { return fmt("%s(std::move(%s))", x.id, x.id); }),
                       ", ");

        inline_code += fmt("inline %s::%s(%s) : %s {\n%s%s}\n\n", type_name, type_name, ctor_args, ctor_inits,
                           init_locals_user(), init_locals_non_user());
    }

    if ( locals_user.size() ) {
        // Create constructor taking the struct's (non-function) fields.
        auto ctor_args = util::join(util::transform(locals_user,
                                                    [&](const auto& x) {
                                                        auto& l = std::get<declaration::Local>(x);
                                                        return fmt("std::optional<%s> %s", l.type, l.id);
                                                    }),
                                    ", ");

        auto ctor_inits =
            util::join(util::transform(locals_user,
                                       [&](const auto& x) {
                                           auto& l = std::get<declaration::Local>(x);
                                           return fmt("    if ( %s ) this->%s = std::move(*%s);\n", l.id, l.id, l.id);
                                       }),
                       "");

        inline_code +=
            fmt("inline %s::%s(%s) : %s() {\n%s}\n\n", type_name, type_name, ctor_args, type_name, ctor_inits);
    }

    return inline_code;
}

std::string cxx::type::Union::str() const {
    std::vector<std::string> types;
    std::vector<std::string> visitor_calls;

    for ( const auto&& [idx, member] : util::enumerate(members) ) {
        auto decl = std::get<declaration::Local>(member);
        types.emplace_back(decl.type);
        visitor_calls.emplace_back(fmt("_(\"%s\", std::get_if<%d>(&this->value)); ", decl.id, idx + 1));
    }

    auto base = fmt("::hilti::rt::Union<%s>", util::join(types, ", "));
    auto header = fmt("    using %s::Union;", base);
    auto visit = fmt("    template<typename F> void __visit(F _) const { %s}", util::join(visitor_calls, ""));
    return fmt("struct %s : public %s {\n%s\n%s\n}", type_name, base, header, visit);
}

std::string cxx::type::Enum::str() const {
    auto vals =
        util::join(util::transform(labels, [](const auto& l) { return fmt("%s = %d", l.first, l.second); }), ", ");

    return fmt("HILTI_RT_ENUM_WITH_DEFAULT(%s, Undef, %s);", type_name, vals);
}

cxx::Formatter& cxx::operator<<(cxx::Formatter& f, const cxx::Block& x) {
    auto braces = (f.ensure_braces_for_block || x.ensureBracesForBlock() || x._stmts.size() > 1 ||
                   (x.size() == 1 && x.size(true) == 0));

    if ( x._stmts.empty() && x._tmps.empty() && ! braces )
        return f;

    auto compact_block = f.compact_block;
    auto eos_after_block = f.eos_after_block;
    auto ensure_braces_for_block = f.ensure_braces_for_block;
    auto sep_after_block = f.sep_after_block;

    f.ensure_braces_for_block = false;
    f.compact_block = false;
    f.eos_after_block = false;
    f.sep_after_block = true;

    if ( braces && compact_block )
        f << "{ ";

    if ( braces && ! compact_block )
        f << '{' << indent() << eol();

    if ( ! braces && ! compact_block )
        f << indent() << eol();

    if ( ! x._stmts.empty() || ! x._tmps.empty() ) {
        for ( const auto& t : x._tmps )
            f << t << ";";

        if ( ! x._tmps.empty() )
            f << separator();

        for ( const auto&& [i, y] : util::enumerate(x._stmts) ) {
            auto [s, b, fl] = y;

            if ( fl & flags::AddSeparatorBefore && i != 0 )
                f << separator();

            if ( fl & flags::BlockEos ) {
                f << s;
                f.eos_after_block = true;
                f << b;
            }
            else {
                if ( ! b ) {
                    f << s;

                    if ( b.ensureBracesForBlock() )
                        f << ' ';
                    else if ( compact_block )
                        f << ';';
                    else
                        f << eos();

                    f << b;
                }
                else {
                    if ( ! s.empty() )
                        f << s << ' ';

                    f.sep_after_block = ! (fl & flags::NoSeparator);

                    if ( s.empty() )
                        f << separator();

                    f << b;

                    if ( s.empty() )
                        f << separator();
                }
            }

            if ( fl & flags::AddSeparatorAfter && i != (x._stmts.size() - 1) )
                f << separator();
        }
    }

    if ( braces && compact_block ) {
        if ( eos_after_block )
            f << " }" << eos();
        else
            f << " }" << eol();
    }

    if ( braces && ! compact_block ) {
        f << dedent();
        if ( eos_after_block )
            f << '}' << eos() << separator();
        else {
            f << '}' << eol();

            if ( ensure_braces_for_block && sep_after_block )
                f << separator();
        }
    }

    if ( ! braces && ! compact_block )
        f << dedent();

    return f;
}

cxx::Formatter& cxx::operator<<(cxx::Formatter& f, const cxx::Expression& x) { return f << std::string(x); }

cxx::Formatter& cxx::operator<<(cxx::Formatter& f, const cxx::ID& x) {
    if ( x.namespace_() == f.namespace_() )
        return f << x.local().str();

    return f << x.str();
}

cxx::Formatter& cxx::operator<<(cxx::Formatter& f, const cxx::Type& x) {
    return f << util::replace(x, fmt("%s::", *f.namespace_(0)), "");
}

cxx::Formatter& cxx::operator<<(cxx::Formatter& f, const cxx::declaration::Type& x) {
    auto id = x.id.local();

    if ( x.id.namespace_() )
        id = cxx::ID(x.id.namespace_(), id);

    f.enterNamespace(id.namespace_());

    if ( ! x.no_using && id.local() && ! util::startsWith(x.type, "struct") )
        f << fmt("using %s = ", id.local()) << x.type << eos();
    else
        f << x.type << eos();

    if ( x.type.isMultiLine() )
        f << eol();

    return f;
}

cxx::Formatter& cxx::operator<<(cxx::Formatter& f, const cxx::declaration::IncludeFile& x) {
    return f << fmt("#include <%s>", x.file) << eol();
}

cxx::Formatter& cxx::operator<<(cxx::Formatter& f, const cxx::declaration::Local& x) {
    f << x.type << ' ' << x.id.local();

    if ( x.init )
        f << " = " << *x.init;

    f << eos();

    return f;
}

cxx::Formatter& cxx::operator<<(cxx::Formatter& f, const cxx::declaration::Global& x) {
    f.enterNamespace(x.id.namespace_());

    if ( x.linkage )
        f << x.linkage << ' ';

    f << x.type << ' ' << x.id.local();

    if ( x.init )
        f << " = " << *x.init;

    f << eos();

    return f;
}

cxx::Formatter& cxx::operator<<(cxx::Formatter& f, const cxx::declaration::Function& x) {
    f.enterNamespace(x.id.namespace_());

    if ( x.attribute )
        f << x.attribute << ' ';

    if ( x.linkage )
        f << x.linkage << ' ';

    if ( x.inline_body )
        f << "inline ";

    f << x.prototype(false);

    if ( x.inline_body ) {
        f.ensure_braces_for_block = true;
        f << ' ' << *x.inline_body;
    }
    else
        f << eos();

    return f;
}

cxx::Formatter& cxx::operator<<(cxx::Formatter& f, const cxx::Function& x) {
    if ( x.declaration.attribute )
        f << x.declaration.attribute << ' ';

    if ( x.declaration.linkage )
        f << x.declaration.linkage << ' ';

    f << x.declaration.prototype(true);

    if ( x.default_ )
        f << " = default;" << eol();
    else {
        f.ensure_braces_for_block = true;
        f.compact_block = (x.body.size() <= 1);
        f << ' ' << x.body;
    }

    return f;
}

cxx::Formatter& cxx::operator<<(cxx::Formatter& f, const cxx::declaration::Constant& x) {
    f.enterNamespace(x.id.namespace_());

    if ( x.linkage )
        f << x.linkage << ' ';

    f << "const " << x.type << ' ' << x.id.local();

    if ( x.init )
        f << " = " << *x.init;

    f << eos();

    return f;
}

void cxx::to_json(json& j, const cxx::ID& id) { j = std::string(id); }

void cxx::from_json(const json& j, cxx::ID& id) { id = cxx::ID(j); }

void cxx::declaration::to_json(json& j, const cxx::declaration::Argument& a) {
    j = json{{"id", a.id}, {"type", a.type}};
}

void cxx::declaration::from_json(const json& j, cxx::declaration::Argument& a) {
    a.id = cxx::ID::fromNormalized(j.at("id").get<std::string>());
    a.type = j.at("type").get<std::string>();
}

void cxx::declaration::to_json(json& j, const cxx::declaration::Constant& c) {
    j = json{{"id", c.id}, {"type", c.type}, {"init", c.init ? *c.init : ""}, {"linkage", c.linkage}};
}

void cxx::declaration::from_json(const json& j, cxx::declaration::Constant& c) {
    c.id = j.at("id").get<cxx::ID>();
    c.type = j.at("type").get<std::string>();
    c.init = j.at("init").get<std::string>();
    c.linkage = j.at("linkage").get<std::string>();
}

void cxx::declaration::to_json(json& j, const cxx::declaration::Type& t) {
    j = json{{"id", t.id},
             {"type", t.type},
             {"forward_decl", t.forward_decl},
             {"forward_decl_prio", t.forward_decl_prio}};
}

void cxx::declaration::from_json(const json& j, cxx::declaration::Type& t) {
    t.id = j.at("id").get<cxx::ID>();
    t.type = j.at("type").get<std::string>();
    t.forward_decl = j.at("forward_decl").get<bool>();
    t.forward_decl_prio = j.at("forward_decl_prio").get<bool>();
}

void cxx::declaration::to_json(json& j, const cxx::declaration::Function& f) {
    j = json{{"result", f.result}, {"id", f.id},           {"args", f.args},
             {"const", f.const_},  {"linkage", f.linkage}, {"attribute", f.attribute}};
}

void cxx::declaration::from_json(const json& j, cxx::declaration::Function& f) {
    f.result = j.at("result").get<std::string>();
    f.id = j.at("id").get<cxx::ID>();
    f.args = j.at("args").get<std::vector<Argument>>();
    f.const_ = j.at("const").get<bool>();
    f.linkage = j.at("linkage").get<std::string>();
    f.attribute = j.at("attribute").get<std::string>();
}
