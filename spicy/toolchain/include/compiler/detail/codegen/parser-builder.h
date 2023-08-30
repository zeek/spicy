// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/compiler/context.h>

#include <spicy/ast/aliases.h>
#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>

namespace hilti::type {
class Struct;
} // namespace hilti::type
namespace hilti::builder {
class Builder;
} // namespace hilti::builder

namespace spicy::detail {

class CodeGen;

namespace codegen {

struct ProductionVisitor;

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

namespace detail {
constexpr hilti::util::enum_::Value<LiteralMode> literal_modes[] = {{LiteralMode::Default, "default"},
                                                                    {LiteralMode::Try, "try"},
                                                                    {LiteralMode::Search, "search"}};
} // namespace detail

constexpr auto to_string(LiteralMode cc) { return hilti::util::enum_::to_string(cc, detail::literal_modes); }

namespace look_ahead {

/** Type for storing a look-ahead ID. */
extern const hilti::Type Type;

/**
 * Expression representing "no look-ahead" symbol through a zero, a value
 * different from any look-ahead ID. With 0 being the value, it can be used
 * in a boolean context to evaluate to false.
 */
extern const hilti::Expression None;

/**
 * Expression representing a virtual "end-of-data" symbol through a value
 * different from any look-ahead ID (and also from `None`).
 */
extern const hilti::Expression Eod;

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
    ParserState(const type::Unit& unit, const Grammar& grammar, Expression data, Expression cur);
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
    void printDebug(const std::shared_ptr<hilti::builder::Builder>& b) const;

    /** Unit type that's currently being compiled. */
    std::reference_wrapper<const type::Unit> unit;

    /** Type name of unit type that is currently being compiled. */
    ID unit_id;

    /** True if the current grammar needs look-ahead tracking. */
    bool needs_look_ahead;

    /**< Expression referencing the current parse object. */
    Expression self;

    /**< Expression referencing the stream instance we're working on. */
    Expression data;

    /**< Expression referencing the beginning of the current unit inside data. */
    Expression begin;

    /**< Expression referencing the current view inside 'data'. */
    Expression cur;

    /**< If set, expression referencing a new `cur` to set after parsing the current rule. */
    std::optional<Expression> ncur;

    /**
     * Boolean expression indicating whether the input data can be trimmed
     * once consumed.
     */
    Expression trim;

    /**
     * Expression with the current look-ahead symbol, or `look_ahead::None`
     * if none. Look ahead-symbols are of type `look_ahead::Type`.
     */
    Expression lahead = look_ahead::None;

    /**
     * Expression with a iterator pointing to the end of the current
     * look-ahead symbol. Only well-defined if *lahead* is set.
     */
    Expression lahead_end;

    /** Mode for parsing literals. */
    LiteralMode literal_mode = LiteralMode::Default;

    /**
     * Target for storing extracted capture groups; set only when needed &
     * desired.
     */
    std::optional<Expression> captures;

    /**
     * Expression holding the last parse error if any. This field is set only in sync or trial mode.
     */
    Expression error;
};

/** Generates the parsing logic for a unit type. */
class ParserBuilder {
public:
    ParserBuilder(CodeGen* cg) : _cg(cg) {}

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
    Expression parseMethodExternalOverload1(const type::Unit& t);

    /**
     * Returns an expression referencing the 2nd version of a publicly
     * visible method that implements a unit's parsing logic, to be called
     * from a host application. This version returns the parsed object
     * plus the data remaining after parsing the unit.
     */
    Expression parseMethodExternalOverload2(const type::Unit& t);

    /**
     * Returns an expression referencing the 3rd version of a publicly
     * visible method that implements a unit's parsing logic, to be called
     * from a host application. This version returns a *generic* parse
     * object of type `spicy::rt::ParsedUnit`, plus the data remaining after
     * parsing the unit.
     */
    Expression parseMethodExternalOverload3(const type::Unit& t);

    /**
     * Returns an expression referencing a publicly visible function
     * instantiating a unit's `%context` type. If the unit does not set
     * `%context`, the returned expression will evaluate to null at runtime.
     */
    Expression contextNewFunction(const type::Unit& t);

    /**
     * Adds a unit's external parsing methods to the HILTI struct
     * corresponding to the parse object. Returns the modified type.
     */
    hilti::type::Struct addParserMethods(hilti::type::Struct s, const type::Unit& t, bool declare_only);

    /** Returns statement builder currently being active. */
    auto builder() { return _builders.back(); }

    /** Activates a statement builder for subsequent code. */
    auto pushBuilder(std::shared_ptr<hilti::builder::Builder> b) {
        _builders.emplace_back(b);
        return b;
    }

    /** Creates a new statement builder and activates it for subsequent code. */
    std::shared_ptr<hilti::builder::Builder> pushBuilder();

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
    auto pushBuilder(std::shared_ptr<hilti::builder::Builder> b, const std::function<void()>& func) {
        pushBuilder(b);
        func();
        popBuilder();
        return b;
    }

    /** Generates code that parses an instance of a specific type. */
    Expression parseType(const Type& t, const production::Meta& meta, const std::optional<Expression>& dst);

    /** Generates code that parses an instance of a specific type into an expression yielding a `Result` of `t`. */
    Expression parseTypeTry(const Type& t, const production::Meta& meta, const std::optional<Expression>& dst);

    /** Returns the type for a `parse_stageX` unit method. */
    hilti::type::Function parseMethodFunctionType(std::optional<type::function::Parameter> addl_param = {},
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
    Expression parseLiteral(const Production& p, const std::optional<Expression>& dst);

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
    void waitForInput(const Expression& min, const std::string& error_msg, const Meta& location);

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
    Expression waitForInputOrEod(const Expression& min);

    /**
     * Generates code that waits for more input. If end-of-data is reached
     * before additional input becomes available, it triggers a parse error.
     *
     * @param error_msg message to report with parse error if end-of-data is reached
     * @param location location associated with the operation
     */
    void waitForInput(const std::string& error_msg, const Meta& location);

    /**
     * Generates code that waits for either more input becoming available or
     * end of data being reached..
     *
     * @param location location associated with the operation
     * @return A boolean expression that's true if more bytes have become
     * available, and false if end-of-data has been reached.
     */
    Expression waitForInputOrEod();

    /**
     * Generates code that waits for end-of-data to be obtained (but not
     * necessarily reached).
     */
    void waitForEod();

    /** Returns a boolean expression that's true if EOD has been reached. */
    Expression atEod();

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
    void advanceInput(const Expression& i);

    /**
     * Generates code that sets the current view.
     *
     * @param i expression that's the new view to use.
     */
    void setInput(const Expression& i);

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
    void consumeLookAhead(std::optional<Expression> dst = {});

    /** Generates code that triggers a parse error exception. */
    void parseError(const std::string& error_msg, const Meta& location);

    /** Generates code that triggers a parse error exception. */
    void parseError(const Expression& error_msg, const Meta& location);

    /** Generates code that triggers a parse error exception. */
    void parseError(const std::string& fmt, const std::vector<Expression>& args, const Meta& location);

    /** Called when a field has been updated. */
    void newValueForField(const production::Meta& meta, const Expression& value, const Expression& dd);

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
     * expression that true if container parsing is to continue.
     */
    Expression newContainerItem(const type::unit::item::Field& field, const Expression& self, const Expression& item,
                                bool need_value);

    /**
     * Applies a field's `&convert` expression to a value, and returns the
     * converted result. If the field does not have that attribute set, returns
     * the original value. If destination is given, also saves the result to
     * that destination (and then it might not need create a tmp to store the
     * result in).
     */
    Expression applyConvertExpression(const type::unit::item::Field& field, const Expression& value,
                                      std::optional<Expression> dst = {});

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
    Expression initLoopBody();

    /**
     * Wrap up parsing the body of loop of "something". Must only be called
     * after an earlier `initLoopBody()`. This will abort with a parsing error if
     * the input pointer hasn't moved.
     *
     * @param cookie opaque cookie received from `initLoopBody()`
     * @param l location associated with the loop body
     */
    void finishLoopBody(const Expression& cookie, const Location& l);

    /**
     * Add a guard block around feature-dependent unit code. This helper
     * typically will put feature-dependent code into a conditional which is
     * only executed if the feature is enabled.
     *
     * @param unit unit the code is added for
     * @param features identifiers of the feature, will be combined with OR.
     * @param f callback building the feature-dependent code.
     */
    void guardFeatureCode(const type::Unit& unit, const std::vector<std::string_view>& features,
                          const std::function<void()>& f);

    CodeGen* cg() const { return _cg; }
    std::shared_ptr<hilti::Context> context() const;
    const hilti::Options& options() const;

private:
    friend struct spicy::detail::codegen::ProductionVisitor;
    CodeGen* _cg;

    Expression _parseType(const Type& t, const production::Meta& meta, const std::optional<Expression>& dst,
                          bool is_try);

    std::vector<ParserState> _states;
    std::vector<std::shared_ptr<hilti::builder::Builder>> _builders;
    std::map<ID, Expression> _functions;
    bool _report_new_value_for_field = true;
};

} // namespace codegen
} // namespace spicy::detail
