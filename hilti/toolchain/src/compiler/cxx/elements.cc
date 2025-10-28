// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <cstring>

#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/cxx/elements.h>
#include <hilti/compiler/detail/cxx/formatter.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::cxx::formatter;

using util::fmt;

namespace flags {
static const unsigned int BlockEos = (1U << 0U);           // Add an end-of-statement after block (i.e., ';').
static const unsigned int NoSeparator = (1U << 1U);        // Don't add a separator after block.
static const unsigned int AddSeparatorAfter = (1U << 2U);  // Force adding a separator after block.
static const unsigned int AddSeparatorBefore = (1U << 4U); // Force adding a separator before block.
} // namespace flags

static const std::set<std::string_view> ReservedKeywords = {
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

std::optional<std::string> cxx::normalizeID(std::string_view id) {
    if ( id.empty() )
        return std::nullopt;

    if ( ReservedKeywords.contains(id) )
        return std::string(id) + "_";

    if ( std::ranges::all_of(id, [](auto c) { return std::isalnum(c) || c == '_'; }) )
        // Fast-path: no special-characters, no leading digits.
        return std::nullopt;

    auto buffer_size = (id.size() * 6) + 1;
    char* buffer = reinterpret_cast<char*>(alloca(buffer_size)); // max possible size of modified string
    char* p = buffer;

    for ( auto c : id ) {
        switch ( c ) {
            // We normalize only characters that we expected to see here during codegen.
            case '%': {
                memcpy(p, "0x25", 4); // NOLINT(bugprone-not-null-terminated-result)
                p += 4;
                break;
            }

            case '@': {
                memcpy(p, "0x40", 4); // NOLINT(bugprone-not-null-terminated-result)
                p += 4;
                break;
            }

            case '~': {                 // we expect to see this only at the beginning (for "~finally")
                memcpy(p, "_0x7e_", 6); // NOLINT(bugprone-not-null-terminated-result)
                p += 6;
                break;
            }

            default: {
                *p++ = c;
                break;
            }
        }
    }

    assert(p < buffer + buffer_size);
    return std::string(buffer, p - buffer);
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

inline static std::string fmtDeclaration(const cxx::ID& id, const cxx::Type& type,
                                         const std::vector<cxx::Expression>& args, std::string linkage = "",
                                         std::optional<cxx::Expression> init = {}) {
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
    const auto* c = (const_ ? "const " : "");
    _stmts.emplace_back(fmt("for ( %sauto& %s : %s )", c, id, seq), body, flags::AddSeparatorAfter);
}

// void cxx::Block::addForRange(const Expression& init, bool const_, const ID& id, const Expression& seq,
//                              cxx::Block body) {
//     auto c = (const_ ? "const " : "");
//     _stmts.emplace_back(fmt("for ( %s; %sauto& %s : %s )", init, c, id, seq), body, flags::AddSeparatorAfter);
// }

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
    std::vector<std::string> to_string_fields;

    auto fmt_bitfield = [&](const declaration::Local* x) {
        std::string out;

        if ( ! x->isAnonymous() )
            out = fmt(R"("$%s=("s + )", x->id.local());

        out += fmt("::hilti::rt::bitfield::detail::render(%s, %s, %s)", x->id, *x->typeinfo_bitfield,
                   (x->isAnonymous() ? "true" : "false"));

        if ( ! x->isAnonymous() )
            out += "+ \")\"";

        to_string_fields.emplace_back(std::move(out));
    };

    auto fmt_member = [&](const auto& f) {
        if ( auto x = std::get_if<declaration::Local>(&f) ) {
            if ( auto x = std::get_if<declaration::Local>(&f) ) {
                if ( ! (x->isInternal() || x->linkage == "inline static") ) {
                    if ( x->typeinfo_bitfield )
                        fmt_bitfield(x); // special-case bitfield printing
                    else {
                        auto id = (x->isAnonymous() ? cxx::ID("<anon>") : x->id);
                        to_string_fields.emplace_back(fmt(R"("$%s=" + hilti::rt::to_string(%s))", id, x->id));
                    }
                }
            }

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
        auto dctor = fmt("%s();", type_name);
        auto cctor = fmt("%s(const %s&) = default;", type_name, type_name);
        auto mctor = fmt("%s(%s&&) = default;", type_name, type_name);
        auto cassign = fmt("%s& operator=(const %s&) = default;", type_name, type_name);
        auto massign = fmt("%s& operator=(%s&&) = default;", type_name, type_name);

        for ( auto x : {std::move(dctor), std::move(cctor), std::move(mctor), std::move(cassign), std::move(massign)} )
            struct_fields.emplace_back(std::move(x));

        auto locals_user = util::filter(members, [](const auto& m) {
            auto l = std::get_if<declaration::Local>(&m);
            return l && ! l->isInternal();
        });

        if ( locals_user.size() ) {
            auto locals_ctor_args =
                util::join(util::transform(locals_user,
                                           [&](const auto& x) {
                                               auto& l = std::get<declaration::Local>(x);
                                               return fmt("::hilti::rt::Optional<%s> %s", l.type, l.id);
                                           }),
                           ", ");
            auto locals_ctor = fmt("explicit %s(%s);", type_name, locals_ctor_args);
            struct_fields.emplace_back(std::move(locals_ctor));
        }

        if ( args.size() ) {
            // Add dedicated constructor to initialize the struct's arguments.
            auto params_ctor_args =
                util::join(util::transform(args, [&](const auto& x) { return fmt("%s %s", x.type, x.id); }), ", ");
            auto params_ctor = fmt("%s(%s);", type_name, params_ctor_args);
            struct_fields.emplace_back(params_ctor);
        }
    }

    auto struct_fields_as_str =
        util::join(util::transform(struct_fields, [&](const auto& x) { return fmt("    %s", x); }), "\n");

    std::string has_params;
    if ( args.size() )
        has_params = ", hilti::rt::trait::hasParameters";

    auto to_string = fmt(R"(
    std::string __to_string() const {
        return "["s + %s + "]";
    })",
                         util::join(to_string_fields, R"( + ", "s + )"));

    return fmt("struct %s : ::hilti::rt::trait::isStruct%s, ::hilti::rt::Controllable<%s> {\n%s\n%s\n}", type_name,
               has_params, type_name, struct_fields_as_str, to_string);
}

std::string cxx::type::Struct::code() const {
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
        cxx::Formatter init;
        init.compact_block = false;
        init.ensure_braces_for_block = false;
        init << ctor;

        return init.str() + util::join(util::transform(locals_user,
                                                       [&](const auto& x) {
                                                           auto& l = std::get<declaration::Local>(x);
                                                           return l.init ? fmt("    %s = %s;\n", l.id, *l.init) :
                                                                           std::string();
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

    std::string code;

    // Create default constructor. This initializes user-controlled members
    // only if there are no struct parameters. If there are, we wouldn't have
    // access to them here yet and hence some init expressions might not
    // evaluate. However, in that case we will run through the
    // parameter-based constructors normally anyways, so don't need this
    // here.
    if ( args.size() )
        code += fmt("%s::%s() {\n%s%s}\n\n", type_name, type_name, init_parameters(), init_locals_non_user());
    else
        code += fmt("%s::%s() {\n%s%s%s}\n\n", type_name, type_name, init_parameters(), init_locals_user(),
                    init_locals_non_user());

    if ( args.size() ) {
        // Create constructor taking the struct's parameters.
        auto ctor_args =
            util::join(util::transform(args, [&](const auto& x) { return fmt("%s %s", x.type, x.id); }), ", ");

        auto ctor_inits =
            util::join(util::transform(args,
                                       [&](const auto& x) {
                                           auto arg = x.isPassedByRef() ? fmt("%s", x.id) : fmt("std::move(%s)", x.id);
                                           return fmt("%s(%s)", x.id, arg);
                                       }),
                       ", ");

        code += fmt("%s::%s(%s) : %s {\n%s%s}\n\n", type_name, type_name, ctor_args, ctor_inits, init_locals_user(),
                    init_locals_non_user());
    }

    if ( locals_user.size() ) {
        // Create constructor taking the struct's (non-function) fields.
        auto ctor_args = util::join(util::transform(locals_user,
                                                    [&](const auto& x) {
                                                        auto& l = std::get<declaration::Local>(x);
                                                        return fmt("::hilti::rt::Optional<%s> %s", l.type, l.id);
                                                    }),
                                    ", ");

        auto ctor_inits =
            util::join(util::transform(locals_user,
                                       [&](const auto& x) {
                                           auto& l = std::get<declaration::Local>(x);
                                           return fmt("    if ( %s ) this->%s = std::move(*%s);\n", l.id, l.id, l.id);
                                       }),
                       "");

        code += fmt("%s::%s(%s) : %s() {\n%s}\n\n", type_name, type_name, ctor_args, type_name, ctor_inits);
    }

    return code;
}

std::string cxx::type::Union::str() const {
    std::vector<std::string> types;
    std::vector<std::string> to_string_fields;

    for ( const auto&& [idx, member] : util::enumerate(members) ) {
        auto decl = std::get<declaration::Local>(member);
        types.emplace_back(decl.type);
        to_string_fields.emplace_back(fmt(R"(if ( auto* x = std::get_if<%d>(&this->value) )
            return "$%s=" + hilti::rt::to_string(*x);
        else )",
                                          idx + 1, decl.id));
    }

    auto base = fmt("::hilti::rt::Union<%s>", util::join(types, ", "));
    auto header = fmt("    using %s::Union;", base);
    auto to_string = fmt(R"(
    std::string __to_string() const {
        %s
            return "<unset>";
    })",
                         util::join(to_string_fields, ""));

    return fmt("struct %s : public %s {\n%s\n%s\n}", type_name, base, header, to_string);
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
        f << indent();

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
    else
        return f << x.str();
}

cxx::Formatter& cxx::operator<<(cxx::Formatter& f, const cxx::Type& x) {
    if ( auto ns = f.namespace_(0) )
        return f << util::replace(x, fmt("%s::", ns), "");
    else
        return f << static_cast<std::string>(x);
}

void cxx::declaration::Type::emit(cxx::Formatter& f) const {
    auto id_ = id.local();

    if ( id_.namespace_() )
        id_ = cxx::ID(id.namespace_(), id);

    f.enterNamespace(id.namespace_());

    if ( ! no_using && id.local() && ! util::startsWith(type, "struct") )
        f << fmt("using %s = ", id.local()) << type << eos();
    else
        f << type << eos();

    if ( type.isMultiLine() )
        f << eol();
}

void cxx::declaration::IncludeFile::emit(cxx::Formatter& f) const { f << fmt("#include <%s>", file) << eol(); }

void cxx::declaration::Local::emit(cxx::Formatter& f) const {
    f << type << ' ' << id.local();

    if ( init )
        f << " = " << *init;

    f << eos();
}

void cxx::declaration::Global::emit(cxx::Formatter& f) const {
    f.enterNamespace(id.namespace_());

    if ( linkage )
        f << linkage << ' ';

    f << type << ' ' << id.local();

    if ( init )
        f << " = " << *init;

    f << eos();
}

void cxx::declaration::Argument::emit(cxx::Formatter& f) const { f << std::string(*this); }

void cxx::declaration::Function::emit(cxx::Formatter& f) const {
    const auto needs_separator = (inline_body && inline_body->size() > 1);

    if ( needs_separator )
        f << separator();

    if ( ! body )
        f.enterNamespace(id.namespace_());

    if ( linkage )
        f << linkage << ' ';

    if ( inline_body )
        f << "inline ";

    f << prototype(body.has_value());

    if ( inline_body ) {
        f.ensure_braces_for_block = true;
        f << ' ' << *inline_body;
    }
    else if ( body ) {
        f.ensure_braces_for_block = true;
        f.compact_block = (body->size() <= 1);
        f << ' ' << *body;
    }
    else
        f << eos();

    if ( needs_separator )
        f << separator();
}

void cxx::declaration::Constant::emit(cxx::Formatter& f) const {
    f.enterNamespace(id.namespace_());

    if ( linkage )
        f << linkage << ' ';

    if ( ! util::startsWith(type, "const ") )
        f << "const ";

    f << type << ' ' << id.local();

    if ( init )
        f << " = " << *init;

    f << eos();
}
