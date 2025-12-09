// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include <hilti/compiler/context.h>

#include <spicy/ast/forward.h>

namespace hilti::type {
class Struct;
} // namespace hilti::type

namespace spicy::detail {

class CodeGen;

namespace codegen {

class Grammar;
class Production;
struct ProductionVisitor;

namespace production {
class Meta;
}

/**
 * Conveys to the parsing logic for literals what the caller wants them to
 * do. This is needed to for doing look-ahead parsing, and hence not relevant
 * for fields that aren't literals.
 */
enum class LiteralMode {
    /** Normal parsing: parse field and raise parse error if not possible. */
    Default,

    /**
     * Try to parse the field, but do not raise an error if it fails. If
     * it works, move cur as normal; if it fails, set cur to end.
     */
    Try,

    /**
     * Search for the field in the input. If a match is found, move cur as
     * normal; if it fails, set cur to end.
     */
    Search,

    /** Advance like default parsing would, but don't make value available. */
    Skip,
};

/**
 * Conveys to the parsing logic for types what the caller wants them to do.
 */
enum class TypesMode {
    /** Standard parsing of the type, with full field machinery set up. */
    Default,

    /**
     * Attempt to parse the type using standard machinery, but don't abort
     * parsing with an error if it fails.
     */
    Try,

    /**
     * Attempt to optimize/short-cut parsing of the type, without having the
     * full field machinery set up yet.
     */
    Optimize,
};

namespace detail {
constexpr hilti::util::enum_::Value<LiteralMode> LiteralModes[] = {
    {.value = LiteralMode::Default, .name = "default"},
    {.value = LiteralMode::Try, .name = "try"},
    {.value = LiteralMode::Search, .name = "search"},
};
} // namespace detail

constexpr auto to_string(LiteralMode cc) { return hilti::util::enum_::to_string(cc, detail::LiteralModes); }

namespace look_ahead {

/**
 * Value representing "no look-ahead" symbol through a zero, a value different
 * from any look-ahead ID. With 0 being the value, it can be used in a boolean
 * context to evaluate to false.
 */
const int64_t None = 0;

/**
 * Value representing a virtual "end-of-data" symbol through a value different
 * from any look-ahead ID (and also from `None`).
 */
const int64_t Eod = -1;

} // namespace look_ahead

/**
 * Maintains access to parser state during code generation. The generated
 * parsing code needs to carry various pieces of state through the logic
 * (e.g., the current input data). This struct records the expressions that
 * are holding the current state variables. To change same state (e.g., to
 * temporarily parse different input) one typically creates a copy of the
 * current struct instance and then pushed that onto parser generator's state
 * stack. To change it back, one pops that struct from the stack.
 */
struct ParserState {
    ParserState(Builder* builder, type::Unit* unit, const Grammar& grammar, Expression* data, Expression* cur);
    ParserState(const ParserState& other) = default;
    ParserState(ParserState&& other) = default;
    ParserState& operator=(const ParserState& other) = default;
    ParserState& operator=(ParserState&& other) = default;
    ~ParserState() = default;

    /**
     * Generates code that prints a representation of the state to the
     * `spicy-verbose` debug stream.
     *
     * @param block bock to add the generated code to
     */
    void printDebug(Builder* builder) const;

    /** Unit type that's currently being compiled. */
    type::Unit* unit = nullptr;

    /** Type name of unit type that is currently being compiled. */
    ID unit_id;

    /**< Expression* referencing the current parse object. */
    Expression* self = nullptr;

    /**< Expression* referencing the stream instance we're working on. */
    Expression* data = nullptr;

    /**< Expression* referencing the beginning of the current unit inside data. */
    Expression* begin = nullptr;

    /**< Expression* referencing the current view inside 'data'. */
    Expression* cur = nullptr;

    /**< If set, expression referencing a new `cur` to set after parsing the current rule. */
    Expression* ncur = nullptr;

    /**
     * Boolean expression indicating whether the input data can be trimmed
     * once consumed.
     */
    Expression* trim = nullptr;

    /**
     * Expression* with the current look-ahead symbol, or `look_ahead::None`
     * if none. Look ahead-symbols are of type `look_ahead::QualifiedType*`.
     */
    Expression* lahead = nullptr;

    /**
     * Expression* with a iterator pointing to the end of the current
     * look-ahead symbol. Only well-defined if *lahead* is set.
     */
    Expression* lahead_end = nullptr;

    /** Mode for parsing literals. */
    LiteralMode literal_mode = LiteralMode::Default;

    /**
     * Target for storing extracted capture groups; set only when needed &
     * desired.
     */
    Expression* captures = nullptr;

    /**
     * Expression* holding the last parse error if any. This field is set only in sync or trial mode.
     */
    Expression* error = nullptr;
};

/** Generates the parsing logic for a unit type. */
class ParserBuilder {
public:
    ParserBuilder(CodeGen* cg);

    CodeGen* cg() const { return _cg; }
    ASTContext* context() const;
    const hilti::Options& options() const;

    /**
     * Pushes new parsing state onto the stack. The new state will then be
     * used by any subsequent code generation.
     */
    void pushState(ParserState p) { _states.push_back(std::move(p)); }

    /**
     * Remove the top element from the parsing state stack, switching back to
     * the previous state.
     */
    void popState() { _states.pop_back(); }

    /** Returns the current parsing state. */
    const ParserState& state() const { return _states.back(); }

    /**
     * Returns an expression referencing the 1st version of a publicly
     * visible method that implements a unit's parsing logic, to be called
     * from a host application. This version returns just the data remaining
     * after parsing the unit.
     */
    Expression* parseMethodExternalOverload1(const type::Unit& t);

    /**
     * Returns an expression referencing the 2nd version of a publicly
     * visible method that implements a unit's parsing logic, to be called
     * from a host application. This version returns the parsed object
     * plus the data remaining after parsing the unit.
     */
    Expression* parseMethodExternalOverload2(const type::Unit& t);

    /**
     * Returns an expression referencing the 3rd version of a publicly
     * visible method that implements a unit's parsing logic, to be called
     * from a host application. This version returns a *generic* parse
     * object of type `spicy::rt::ParsedUnit`, plus the data remaining after
     * parsing the unit.
     */
    Expression* parseMethodExternalOverload3(const type::Unit& t);

    /**
     * Returns an expression referencing a publicly visible function
     * instantiating a unit's `%context` type. If the unit does not set
     * `%context`, the returned expression will evaluate to null at runtime.
     */
    Expression* contextNewFunction(const type::Unit& t);

    /**
     * Adds a unit's external parsing methods to the HILTI struct
     * corresponding to the parse object. Returns the modified type.
     */
    void addParserMethods(hilti::type::Struct* s, type::Unit* t, bool declare_only);

    /** Returns statement builder currently being active. */
    Builder* builder() const;

    /** Activates a statement builder for subsequent code. */
    auto pushBuilder(std::shared_ptr<Builder> b) {
        _builders.emplace_back(b);
        return b;
    }

    /** Creates a new statement builder and activates it for subsequent code. */
    std::shared_ptr<Builder> pushBuilder();

    /** Deactivates the most recent statement builder. */
    auto popBuilder() {
        auto x = _builders.back();
        _builders.pop_back();
        return x;
    }

    /** An object whose destructor pops the most recent statement builder. */
    struct ScopeGuard {
        ScopeGuard(ParserBuilder* self) { this->self = self; }
        ScopeGuard(ScopeGuard&&) = default;
        ~ScopeGuard() { self->popBuilder(); }

        ScopeGuard() = delete;
        ScopeGuard(const ScopeGuard&) = delete;
        ScopeGuard& operator=(const ScopeGuard&) = delete;
        ScopeGuard& operator=(ScopeGuard&&) noexcept = delete;

        ParserBuilder* self;
    };

    /** Returns an object whose destructor pops the most recent statement builder. */
    ScopeGuard makeScopeGuard() { return ScopeGuard(this); }

    /** Activates a statement builder for subsequent code. */
    template<typename Func>
    auto pushBuilder(std::shared_ptr<Builder> b, Func&& func) {
        pushBuilder(b);
        func();
        popBuilder();
        return b;
    }

    /**
     * Generates code that parses an instance of a specific type.
     *
     * Advances the current position to the end of the parsed value if
     * successful. If *mode* is `Default` or `Optimize`, raises an error if
     * parsing fails. If *mode* is `Try`, does not raise an error if parsing
     * fails but leaves current position at the beginning of the current view.
     *
     * @param t type to parse
     * @param meta meta information associated with the parsing operation
     * @param dst expression to store the parsed value into; if null, an
     * internal temporary is used to store the result
     * @param mode parsing mode
     * @param no_trim if true, do not trim the input after successfully parsing the instance
     * @returns the expression that holds the parsed value, which will be equal
     * to *dst* if that's non-null; if *mode* is `Optimize`, returns null to if
     * the parsing could not optimized (no state will have changed in that
     * case)
     */
    Expression* parseType(UnqualifiedType* t, const production::Meta& meta, Expression* dst, TypesMode mode,
                          bool no_trim = false);

    /** Returns the type for a `parse_stageX` unit method. */
    hilti::type::Function* parseMethodFunctionType(hilti::type::function::Parameter* addl_param = {},
                                                   const Meta& m = {});

    /**
     * Generates code that parses an instance of a specific literal, meaning
     * it matches the value against the input.
     *
     * In literal mode `Default`, returns the parsed value and advances `cur`,
     * consuming the current look-ahead symbol if any, and throwing a parse
     * error if it couldn't parse it.
     *
     * In literal mode `Try`, returns an iterator pointing right
     * after the parsed literal, with an iterator equal to `begin(cur)`
     * meaning no match (and does not advance `cur`).
     *
     * Literal mode `Search` behaves like `Try`, but will advance the input
     * until a match has been found or EOD is reached.
     */
    Expression* parseLiteral(const Production& p, Expression* dst);

    /**
     * Generates code that skips over an instance of a specific literal,
     * meaning it assumed it will find the value in the input, but not process
     * it further.
     *
     * @param prod a literal production matching what is to be skipped
     */
    void skipLiteral(const Production& production);

    /**
     * Generates code that ensures that a minimum amount of data is available
     * for parsing. The generated code will wait until enough data becomes
     * available before proceeding. It will abort parsing if end-of-data is
     * reached before that.
     *
     * @param min unsigned integer expression specifying the requited number
     * of bytes.
     * @param error_msg message to report with parse error if end-of-data is reached
     * @param location location associated with the operation.
     */
    void waitForInput(Expression* min, std::string_view error_msg, const Meta& location);

    /**
     * Generates code that ensures that either a minimum amount of data is
     * available for parsing, or end-of-data is reached. The generated code
     * will wait until either happens.
     *
     * @param min unsigned integer expression specifying the requited number of
     * bytes.
     *
     * @return A boolean expression that's true if sufficient bytes are
     * available, and false if end-of-data has been reached.
     */
    Expression* waitForInputOrEod(Expression* min);

    /**
     * Generates code that waits for more input. If end-of-data is reached
     * before additional input becomes available, it triggers a parse error.
     *
     * @param error_msg message to report with parse error if end-of-data is reached
     * @param location location associated with the operation
     */
    void waitForInput(std::string_view error_msg, const Meta& location);

    /**
     * Generates code that waits for either more input becoming available or
     * end of data being reached..
     *
     * @param location location associated with the operation
     * @return A boolean expression that's true if more bytes have become
     * available, and false if end-of-data has been reached.
     */
    Expression* waitForInputOrEod();

    /**
     * Generates code that waits for end-of-data to be obtained (but not
     * necessarily reached).
     */
    void waitForEod();

    /*
     * Generates code which waits for given input length to be available to
     * immediately consume and trim it.
     *
     * @param size an unsigned integer specifying the length of the input to skip
     * @param location location associated with the operation
     */
    void skip(Expression* size, const Meta& location = {});

    /** Returns a boolean expression that's true if EOD has been reached. */
    Expression* atEod();

    /**
     * Generates code that advances the current view to the next position which is not a gap.
     * This implicitly calls advancedInput() afterwards.
     */
    void advanceToNextData();

    /**
     * Generates code that advances the current view to a new start position.
     * This implicitly calls advancedInput() afterwards.
     *
     * @param i expression that's either the number of bytes to move ahead,
     * a stream iterator to move to, or a new stream view to use from now on.
     */
    void advanceInput(Expression* i);

    /**
     * Generates code that sets the current view.
     *
     * @param i expression that's the new view to use.
     */
    void setInput(Expression* i);

    /**
     * Generates code that saves the current parsing position inside the
     * current parse object. This only has an effect for unit types that
     * support random access, it's a no-op for others.
     */
    void saveParsePosition();

    /** Inserts code that needs to run before a user hook gets executed. */
    void beforeHook();

    /** Inserts code that needs to run after a user hook was executed. */
    void afterHook();

    /**
     * Generates code that consumes the current look-ahead symbol. It clears
     * `lahead`, move `cur` to `lahead_end`, and optionally stores the
     * look-ahead token itself into a custom destination.
     *
     * @param dst A RHS expression of type bytes to store the token into.
     */
    void consumeLookAhead(Expression* dst = nullptr);

    /** Generates code that triggers a parse error exception. */
    void parseError(std::string_view error_msg, const Meta& meta = {});

    /** Generates code that triggers a parse error exception. */
    void parseError(Expression* error_msg, const Meta& meta = {});

    /** Generates code that triggers a parse error exception. */
    void parseError(std::string_view fmt, const Expressions& args, const Meta& meta = {});

    /** Generates code that triggers a parse error exception. */
    void parseError(std::string_view fmt, Expression* orig_except);

    /** Called when a field has been updated. */
    void newValueForField(const production::Meta& meta, Expression* value, Expression* dd);

    /**
     * Signal that new values for fields are reported through custom logic,
     * disable default reporting for current field.
     */
    void enableDefaultNewValueForField(bool enable) { _report_new_value_for_field = enable; };

    /**
     * Returns true if default reporting of new value is enabled for the
     * current field.
     */
    bool isEnabledDefaultNewValueForField() { return _report_new_value_for_field; }

    /**
     * Called when a container item has been parsed. Returns a boolean
     * expression that is true if container parsing is to continue.
     */
    Expression* newContainerItem(const type::unit::item::Field* field, const type::unit::item::Field* container,
                                 Expression* self, Expression* item, bool need_value);

    /**
     * Applies a field's `&convert` expression to a value, and returns the
     * converted result. If the field does not have that attribute set, returns
     * the original value. If destination is given, also saves the result to
     * that destination (and then it might not need create a tmp to store the
     * result in).
     */
    Expression* applyConvertExpression(const type::unit::item::Field& field, Expression* value, Expression* dst = {});

    /**
     * Trims the input's beginning to the current parsing position,
     * discarding all data preceding it. By default, this does not do
     * anything if the current parsing state does not allow trimming.
     *
     * @param force always trim, independent of the parsing state's trimming state
     */
    void trimInput(bool force = false);

    /**
     * Generates code that initializes a unit instance just before parsing
     * begins.
     *
     * @param l location to associate with the generated code
     */
    void initializeUnit(const Location& l);

    /**
     * Generates code that cleans up a unit instances after parsing has
     * finished, normally or abnormally.
     *
     * @param success true if parsing was successful, false if an error occurred.
     * @param l location to associate with the generated code
     */
    void finalizeUnit(bool success, const Location& l);

    /** Prepare for backtracking via ``&try``. */
    void initBacktracking();

    /** Clean up after potential backtracking via ``&try``. */
    void finishBacktracking();

    /**
     * Prepare for parsing the body of a loop of "something". Must be followed
     * by calling `finishLoopBody()` once parsing is done.
     *
     * @returns an opaque cookie to pass into `finishLoopBody()`.
     */
    Expression* initLoopBody();

    /**
     * Wrap up parsing the body of loop of "something". Must only be called
     * after an earlier `initLoopBody()`. This will abort with a parsing error if
     * the input pointer hasn't moved.
     *
     * @param cookie opaque cookie received from `initLoopBody()`
     * @param l location associated with the loop body
     */
    void finishLoopBody(Expression* cookie, const Location& l);

    /**
     * Add a guard block around feature-dependent unit code. This helper
     * typically will put feature-dependent code into a conditional which is
     * only executed if the feature is enabled.
     *
     * @param unit unit the code is added for
     * @param features identifiers of the feature, will be combined with OR.
     * @param f callback building the feature-dependent code.
     */
    template<typename Func>
    void guardFeatureCode(const type::Unit* unit, const std::vector<std::string_view>& features, Func&& f) {
        if ( ! features.empty() )
            pushBuilder(_featureCodeIf(unit, features));

        f();

        if ( ! features.empty() )
            popBuilder();
    }

    /**
     * Call the `%sync_advance` hook with the invocation wrapped in a feature
     * guard. The parameter allows injecting an additional condition which will
     * be checked inside the guard.
     *
     * @param cond an additional, optional condition to check before invoking
     *             the hook.
     */
    void syncAdvanceHook(std::shared_ptr<Builder> cond = {});

    /**
     * Returns an expression referencing the current parse object's
     * `HILTI_INTERNAL(filters)` member if that exists; otherwises return a
     * `Null` expression. The result of this method can be passed to runtime
     * functions expecting a `HILTI_INTERNAL(filters)` argument.
     *
     * @param state current parser state
     */
    Expression* currentFilters(const ParserState& state);

    QualifiedType* lookAheadType() const;
    hilti::Expression* featureConstant(const type::Unit* unit, std::string_view feature);

    /** Adds a temporary to store an attribute's expression, if necessary. */
    Expression* evaluateAttributeExpression(const hilti::Attribute* attr, const std::string& prefix);

    /*
     * Filters a set of field attributes to remove those that are handled
     * generically by the field parsing machinery that the parser builder sets
     * up itself; in contrast to attributes that must be handled by
     * field-specific parsing code. For example, the `&convert` attribute is a
     * generic attributes, whereas `&byte-order` is not.
     *
     * Note that the concrete semantics remain a bit fuzzy here because
     * attribute semantics aren't always clear-cut. For example, `&size` is
     * generally handled generically, but may still control field-specific
     * code in some cases. The main purpose of this method is to weed out
     * attributes that field-specific code normally doesn't need to care about
     * when checking for attributes it needs to handle (and the method does
     * remove `&size`). If in doubt, look at the full set of attributes
     * instead.
     *
     * @param attrs the set of attributes to filter
     * @return a new set of attributes with the generic ones removed; the
     * pointers are shared with the original set
     */
    static hilti::Attributes removeGenericParseAttributes(hilti::AttributeSet* attrs);

private:
    friend struct spicy::detail::codegen::ProductionVisitor;

    std::shared_ptr<Builder> _featureCodeIf(const type::Unit* unit, const std::vector<std::string_view>& features);

    CodeGen* _cg;
    std::vector<ParserState> _states;
    std::vector<std::shared_ptr<Builder>> _builders;
    std::map<ID, Expression*> _functions;
    bool _report_new_value_for_field = true;
};

} // namespace codegen
} // namespace spicy::detail
