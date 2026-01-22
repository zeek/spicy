// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/base/id-base.h>
#include <hilti/base/util.h>

namespace hilti::detail::cxx {

class Formatter;

namespace element {
enum class Type { Expression, Type, Linkage, Attribute };
} // namespace element

/** An element of type `T` in the compiler's intermediary C++ representation. */
template<element::Type T>
class Element {
public:
    Element() = default;
    Element(std::string s) : _s(std::move(s)) {}
    Element(const char* s) : _s(s) {}

    Element& operator=(const std::string& s) {
        _s = s;
        return *this;
    }
    Element& operator=(std::string&& s) {
        _s = std::move(s);
        return *this;
    }
    Element& operator=(const char* s) {
        _s = s;
        return *this;
    }

    bool isMultiLine() const { return _s.find('\n') != std::string::npos; }

    operator std::string() const { return _s; }
    operator std::string_view() const { return _s; }
    explicit operator bool() const { return ! _s.empty(); }
    bool operator<(const Element& s) const { return _s < s._s; }
    bool operator==(const Element& s) const { return _s == s._s; }
    bool operator!=(const Element& s) const { return ! operator==(s); }

private:
    std::string _s;
};

using Attribute = Element<element::Type::Attribute>; /**< C++ function attribute */
using Linkage = Element<element::Type::Linkage>;     /**< C++ linkage specification */
using Type = Element<element::Type::Type>;           /**< C++ type */

/**
 * Represents a C++-side expression, stored as a string of the C++ code along
 * with a associated "side".
 */
class Expression {
public:
    Expression() = default;
    Expression(std::string s, Side side = Side::RHS) : _s(std::move(s)), _side(side) {}
    Expression(const char* s, Side side = Side::RHS) : _s(s), _side(side) {}

    bool isLhs() const { return _side == Side::LHS; }

    operator std::string() const { return _s; }
    operator std::string_view() const { return _s; }
    explicit operator bool() const { return ! _s.empty(); }
    bool operator<(const Expression& s) const { return _s < s._s; }
    bool operator==(const Expression& s) const { return _s == s._s; }
    bool operator!=(const Expression& s) const { return ! operator==(s); }

private:
    std::string _s;
    Side _side = Side::LHS;
};

extern std::optional<std::string> normalizeID(std::string_view id);

/** A C++ ID. */
class ID : public detail::IDBase<ID, normalizeID> {
public:
    using Base = detail::IDBase<ID, normalizeID>;

    /** Creates an empty ID. */
    ID() {}

    /** Creates an ID from an (not normalized) string. */
    ID(const char* s) : Base(s) {}
    explicit ID(std::string_view s) : Base(s) {}

    /**
     * Creates an ID from a string that's already normalized. The assumption is
     * that the input string is the output of a prior `str()` call on an
     * existing ID object.
     */
    ID(std::string_view s, AlreadyNormalized n) : Base(s, n) {}

    /** Concatenates multiple strings into a single ID, separating them with `::`. */
    template<typename... T,
             typename enable = std::enable_if_t<
                 (... && std::is_convertible_v<
                             T, // NOLINT(modernize-type-traits), see https://github.com/llvm/llvm-project/issues/110502
                             std::string_view>)>>
    explicit ID(const T&... s) : Base(s...) {}


    /** Concatenates multiple strings into a single ID, separating them with `::`. */
    ID(std::initializer_list<std::string_view> x) : Base(x) {}

    ID(const Base& other) : Base(other) {}

    ID(Base&& other) noexcept : Base(other) {}

    ID& operator=(const ::hilti::ID& id) {
        *this = ID(id);
        return *this;
    }

    /** Wrapper to construct an ID from an already normalized string name. */
    static ID fromNormalized(std::string_view id) { return ID(id, Base::AlreadyNormalized()); }
};

namespace declaration {

// Joint base class for all C++ declarations.
struct DeclarationBase {
    DeclarationBase(cxx::ID id) : id(std::move(id)) {}
    virtual ~DeclarationBase() = default;

    cxx::ID id;

    // Outputs the C++ representation of the declaration.
    virtual void emit(Formatter& f) const = 0;

protected:
    bool operator==(const DeclarationBase& other) const { return id == other.id; } // for derived classes to use
};

/** A C++ `@include` specific action. */
struct IncludeFile : public DeclarationBase {
    IncludeFile(std::string file) : DeclarationBase({}), file(std::move(file)) {}

    std::string file;

    void emit(Formatter& f) const final;

    bool operator<(const IncludeFile& other) const { return file < other.file; }
    bool operator==(const IncludeFile& other) const { return file == other.file && DeclarationBase::operator==(other); }
    bool operator!=(const IncludeFile& other) const { return ! operator==(other); }
};

/** Declaration of a local C++ variable. */
struct Local : public DeclarationBase {
    Local(cxx::ID id = {}, cxx::Type type = {}, std::vector<cxx::Expression> args = {},
          std::optional<cxx::Expression> init = {}, Linkage linkage = {})
        : DeclarationBase(std::move(id)),
          type(std::move(type)),
          args(std::move(args)),
          init(std::move(init)),
          linkage(std::move(linkage)) {}

    struct NotEmittedTag {};
    Local(cxx::ID id, cxx::Type type, NotEmittedTag /* not used */)
        : DeclarationBase(std::move(id)), type(std::move(type)), emitted(false) {}

    cxx::Type type;
    std::vector<cxx::Expression> args;
    std::optional<cxx::Expression> init;
    Linkage linkage;
    bool emitted = true; // for struct fields: if false, the field is not emitted into the generated type
    std::optional<cxx::Expression> typeinfo_bitfield; // for rendering anonymous bitfields inside structs

    // Returns true if the ID starts with the prefix for internal IDs, which is
    // the namespace reserved for internal IDs.
    bool isInternal() const { return util::startsWith(id.local(), HILTI_INTERNAL_ID("")); }

    // Returns true if the ID starts with "_anon", which is the marker we use
    // for anonymous fields that make it out into the generated struct.
    bool isAnonymous() const { return util::startsWith(id.local(), "_anon"); }

    void emit(Formatter& f) const final;

    bool operator==(const Local& other) const {
        return type == other.type && args == other.args && init == other.init && linkage == other.linkage &&
               DeclarationBase::operator==(other);
    }

    bool operator!=(const Local& other) const { return ! operator==(other); }

    std::string str() const;
    operator std::string() const { return str(); }
};

/** Declaration of a global C++ variable. */
struct Global : public DeclarationBase {
    cxx::Type type;
    std::vector<cxx::Expression> args;
    std::optional<cxx::Expression> init;
    Linkage linkage;

    Global(cxx::ID id = {}, cxx::Type type = {}, std::vector<cxx::Expression> args = {},
           std::optional<cxx::Expression> init = {}, Linkage linkage = {})
        : DeclarationBase(std::move(id)),
          type(std::move(type)),
          args(std::move(args)),
          init(std::move(init)),
          linkage(std::move(linkage)) {}

    void emit(Formatter& f) const final;

    bool operator==(const Global& other) const {
        return type == other.type && args == other.args && init == other.init && linkage == other.linkage &&
               DeclarationBase::operator==(other);
    }

    bool operator!=(const Global& other) const { return ! operator==(other); }

    std::string str() const;
    operator std::string() const { return str(); }
};

/** Declaration of a C++ constant. */
struct Constant : public DeclarationBase {
    cxx::Type type;
    std::optional<cxx::Expression> init;
    Linkage linkage;

    Constant(cxx::ID id = {}, cxx::Type type = {}, std::optional<cxx::Expression> init = {}, Linkage linkage = {})
        : DeclarationBase(std::move(id)), type(std::move(type)), init(std::move(init)), linkage(std::move(linkage)) {}

    void emit(Formatter& f) const final;

    bool operator<(const Constant& s) const { return id < s.id; }
    bool operator==(const Constant& other) const {
        return type == other.type && init == other.init && linkage == other.linkage &&
               DeclarationBase::operator==(other);
    }

    bool operator!=(const Constant& other) const { return ! operator==(other); }
};

/** Declaration of a C++ type. */
struct Type : public DeclarationBase {
    cxx::Type type;
    std::string code;
    bool no_using = false; // turned on automatically for types starting with "struct"
    bool public_ = false;  // declare the type in a public section of the generated C++ code

    Type(cxx::ID id = {}, cxx::Type type = {}, std::string code = {}, bool no_using = false, bool public_ = false)
        : DeclarationBase(std::move(id)),
          type(std::move(type)),
          code(std::move(code)),
          no_using(no_using),
          public_(public_) {}

    void emit(Formatter& f) const final;

    bool operator==(const Type& other) const {
        return type == other.type && code == other.code && no_using == other.no_using &&
               DeclarationBase::operator==(other);
    }

    bool operator!=(const Type& other) const { return ! operator==(other); }
};

/** Declaration of a C++ function argument. */
struct Argument : public DeclarationBase {
    cxx::Type type;
    std::optional<cxx::Expression> default_;
    cxx::Type internal_type = "";
    operator std::string() const { return id ? util::fmt("%s %s", type, id) : std::string(type); }

    Argument(cxx::ID id = {}, cxx::Type type = {}, std::optional<cxx::Expression> default_ = {},
             cxx::Type internal_type = "")
        : DeclarationBase(std::move(id)),
          type(std::move(type)),
          default_(std::move(default_)),
          internal_type(std::move(internal_type)) {}

    void emit(Formatter& f) const final;

    bool operator==(const Argument& other) const {
        return type == other.type && default_ == other.default_ && internal_type == other.internal_type &&
               DeclarationBase::operator==(other);
    }

    bool operator!=(const Argument& other) const { return ! operator==(other); }

    bool isPassedByRef() const { return std::string_view(type).ends_with("&"); }
};

} // namespace declaration

/** A C++ statement block. */
class Block {
public:
    Block() {}
    Block(std::vector<std::string> stmts);

    void addStatement(std::string stmt);
    void addStatementAtFront(std::string stmt);
    void addBlock(Block child);
    void addComment(const std::string& stmt, bool sep_before = true, bool sep_after = false);
    void addLocal(const declaration::Local& v);
    void addTmp(const declaration::Local& v);
    void addReturn(const Expression& expr = Expression());
    void addIf(const Expression& cond, Block true_);
    void addIf(const Expression& init, const Expression& cond, cxx::Block true_);
    void addIf(const Expression& cond, Block true_, Block false_);
    void addIf(const Expression& init, const Expression& cond, Block true_, Block false_);
    void addElseIf(const Expression& cond, Block true_);
    void addElse(Block true_);
    void addFor(const Expression& init, const Expression& cond, const Expression& next, const cxx::Block& body);
    void addForRange(bool const_, const ID& id, const Expression& seq, const cxx::Block& body);
    // void addForRange(const Expression& init, bool const_, const ID& id, const Expression& seq, cxx::Block body); //
    // C++20 ...
    void addWhile(const Expression& cond, const Block& body);
    void addLambda(const std::string& name, const std::string& signature, Block body);
    void addSwitch(const Expression& cond, const std::vector<std::pair<Expression, Block>>& cases_,
                   std::optional<Block> default_ = {});
    void appendFromBlock(Block b);
    void addTry(Block body, std::vector<std::pair<declaration::Argument, Block>> catches);

    bool ensureBracesForBlock() const { return _ensure_braces_for_block; }
    void setEnsureBracesforBlock() { _ensure_braces_for_block = true; }

    size_t size(bool ignore_comments = false) const;

    Block& operator+=(const Block& other);

    explicit operator bool() const { return ! (_stmts.empty() && _tmps.empty()); }

    friend ::hilti::detail::cxx::Formatter& operator<<(Formatter& f, const Block& x);

    bool operator==(const Block& other) const { return _stmts == other._stmts; }
    bool operator!=(const Block& other) const { return ! operator==(other); }

private:
    using Flags = unsigned int;
    std::vector<std::tuple<std::string, Block, Flags>> _stmts;
    std::vector<std::string> _tmps;
    bool _ensure_braces_for_block = false;
};

namespace declaration {


/** Declaration of a C++ function. */
struct Function : public DeclarationBase {
    /** Tag marking an inline function for overload resolution. */
    using Inline = struct {};

    /** Type of function being declared. */
    enum Type {
        Free,  // global, free function
        Method // struct method
    };

    Type ftype;
    cxx::Type result;
    std::vector<Argument> args;
    Linkage linkage;
    std::optional<Block> body;
    std::optional<Block> inline_body;

    std::string prototype(bool qualify) const;
    std::string parameters() const;

    Function(Type ftype, cxx::Type result, cxx::ID id, std::vector<Argument> args, Linkage linkage,
             std::optional<Block> body = {})
        : DeclarationBase(std::move(id)),
          ftype(ftype),
          result(std::move(result)),
          args(std::move(args)),
          linkage(std::move(linkage)),
          body(std::move(body)) {}

    Function(Type ftype, cxx::Type result, cxx::ID id, std::vector<Argument> args, Linkage linkage, Inline,
             Block inline_body)
        : DeclarationBase(std::move(id)),
          ftype(ftype),
          result(std::move(result)),
          args(std::move(args)),
          linkage(std::move(linkage)),
          inline_body(std::move(inline_body)) {}

    void emit(Formatter& f) const final;

    bool operator==(const Function& other) const {
        return ftype == other.ftype && result == other.result && args == other.args && linkage == other.linkage &&
               inline_body == other.inline_body && body == other.body && DeclarationBase::operator==(other);
    }

    bool operator!=(const Function& other) const { return ! operator==(other); }
};

} // namespace declaration

namespace type {
namespace struct_ {

using Member = std::variant<declaration::Local, declaration::Function>;

inline bool operator<(const Member& m1, const Member& m2) {
    auto id = [](auto m) {
        if ( auto x = std::get_if<declaration::Local>(&m) )
            return x->id;
        if ( auto x = std::get_if<declaration::Function>(&m) )
            return x->id;

        throw std::bad_variant_access();
    };

    return id(m1) < id(m2);
}

} // namespace struct_

/** A C++ struct type. */
struct Struct {
    std::vector<declaration::Argument> args;
    std::vector<struct_::Member> members;
    cxx::ID type_name;
    std::optional<cxx::Type> self;
    cxx::Block ctor;
    bool add_ctors = false;
    std::string str() const;
    std::string code() const;

    operator std::string() const { return str(); }
    operator cxx::Type() const { return str(); }
};

namespace union_ {
using Member = struct_::Member;
} // namespace union_

/** A C++ union type. */
struct Union {
    std::vector<union_::Member> members;
    cxx::ID type_name;
    std::string str() const;
    operator std::string() const { return str(); }
    operator cxx::Type() const { return str(); }
};

namespace enum_ {
using Label = std::pair<cxx::ID, int>;
} // namespace enum_

/** A C++ enum type. */
struct Enum {
    std::vector<enum_::Label> labels;
    cxx::ID type_name;
    std::string str() const;
    operator std::string() const { return str(); }
    operator cxx::Type() const { return str(); }
};

} // namespace type

inline std::ostream& operator<<(std::ostream& o, const ID& i) { return o << std::string(i); }
inline std::ostream& operator<<(std::ostream& o, const Linkage& l) { return o << std::string(l); }
inline std::ostream& operator<<(std::ostream& o, const Type& t) { return o << std::string(t); }
inline std::ostream& operator<<(std::ostream& o, const Attribute& a) { return o << std::string(a); }
inline std::ostream& operator<<(std::ostream& o, const declaration::Argument& t) { return o << std::string(t); }
inline std::ostream& operator<<(std::ostream& o, const Expression& e) { return o << std::string(e); }

extern Formatter& operator<<(Formatter& f, const Block& x);
extern Formatter& operator<<(Formatter& f, const Expression& x);
extern Formatter& operator<<(Formatter& f, const ID& x);
extern Formatter& operator<<(Formatter& f, const Function& x);
extern Formatter& operator<<(Formatter& f, const Type& x);

inline Formatter& operator<<(Formatter& f, const declaration::DeclarationBase& x) {
    x.emit(f);
    return f;
}

} // namespace hilti::detail::cxx
