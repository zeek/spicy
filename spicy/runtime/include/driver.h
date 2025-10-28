// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/rt/result.h>

#include <spicy/rt/parser.h>

namespace spicy::rt {

class Driver;

namespace driver {

enum class ParsingType { Stream, Block };

/**
 * Abstract base class maintaining the parsing state during incremental input
 * processing.
 */
class ParsingState {
public:
    /**
     * Constructor.
     *
     * @param type of parsing; this determines how subsequent chunks of input
     * data are handled (stream-wise vs independent blocks)
     *
     * @param parser parser to use; can be left unset to either not perform any
     * parsing at all, or set it later through `setParser()`; only parsers that
     * do not take any unit parameters are supported, otherwise a
     * `InvalidUnitType`  exception will be thrown at runtime.
     *
     * @param context context to make available to unit instance during parsing
     */
    ParsingState(ParsingType type, const Parser* parser = nullptr, hilti::rt::Optional<UnitContext> context = {})
        : _type(type), _parser(parser), _context(std::move(context)) {}

    /**
     * Returns false if a parser has neither been passed into the constructor
     * nor explicitly set through `setParser()`.
     */
    bool hasParser() const { return _parser != nullptr; }

    /**
     * Explicitly sets a parser to use. Once stream-based matching has started,
     * changing a parser won't have any effect. Only parsers that do not take
     * any unit parameters are supported, otherwise a `InvalidUnitType`
     * exception will be thrown at runtime.
     *
     * @param parser parser to use; can be left unset to either not perform
     * any parsing at all, or set it later through `setParser()`.
     *
     * @param context context to make available to unit instance during parsing
     */
    void setParser(const Parser* parser, hilti::rt::Optional<UnitContext> context = {}) {
        _parser = parser;
        _context = std::move(context);
    }

    /**
     * Returns true if parsing has finished due to either: regularly reaching
     * the end of input or end of grammar, a parsing error, explicit skipping
     * of remaining input.
     */
    bool isFinished() const { return _done || _skip; }

    /**
     * Explicitly skips any remaining input. Further calls to `process()` and
     * `finish()` will be ignored.
     */
    void skipRemaining() { _skip = true; }

    /** Returns true if `skipRemaining()` has been called previously. */
    bool isSkipping() const { return _skip; }

    /** Helper type for capturing return value of `process()`. */
    enum State {
        Done,    /**< parsing has fully finished */
        Continue /**< parsing remains ongoing and ready to accept for data */
    };

    /**
     * Feeds one chunk of data into parsing. If we're doing stream-based
     * parsing, this sends the data into the stream processing as the next
     * piece of input. If we're doing block-based parsing, the data must
     * constitute a complete self-contained block of input, so that the
     * parser can fully consume it as one unit instance.
     *
     * @param size length of data
     * @param data pointer to *size* bytes to feed into parsing. If this is a nullptr a gap of length *size* will be
     * processed.
     * @returns Returns `State` indicating if parsing remains ongoing or has finished.
     * @throws any exceptions (including in particular parse errors) are
     * passed through to caller
     */
    State process(size_t size, const char* data) { return _process(size, data, false); }

    /**
     * Finalizes parsing, signaling end-of-data to the parser. After calling
     * this, `process()` can no longer be called.
     *
     * @throws any exceptions (including in particular final parse errors)
     * are passed through to caller
     */
    hilti::rt::Optional<hilti::rt::stream::Offset> finish();

    /**
     * Resets parsing back to its original state as if no input had been sent
     * yet. Initialization information passed into the constructor, as well
     * as any parser explicitly set, is retained.
     */
    void reset() {
        _input.reset();
        _resumable.reset();
        _done = false;
        _skip = false;
    }

protected:
    /**
     * Virtual method to override by derived classed for recording debug
     * output. Note that in a release mode compile the driver code will not
     * actually call this (nor should user code probably).
     */
    virtual void debug(const std::string& msg) = 0;

    /**
     * Forwards to `debug(msg)`, also including a hexdump of the given data.
     */
    void debug(const std::string& msg, size_t size, const char* data);

private:
    State _process(size_t size, const char* data, bool eod = true);

    ParsingType _type;                         /**< type of parsing */
    const Parser* _parser;                     /**< parser to use, or null if not specified */
    bool _skip = false;                        /**< true if all further input is to be skipped */
    hilti::rt::Optional<UnitContext> _context; /** context to make available to parsing unit */

    // State for stream matching only
    bool _done = false; /**< flag to indicate that stream matching has completed (either regularly or irregularly) */
    hilti::rt::Optional<hilti::rt::ValueReference<hilti::rt::Stream>> _input; /**< Current input data */
    hilti::rt::Optional<hilti::rt::Resumable> _resumable; /**< State for resuming parsing on next data chunk */
};

/** Specialized parsing state for use by *Driver*. */
class ParsingStateForDriver : public ParsingState {
public:
    /**
     * Constructor.
     *
     * @param type of parsing; this determines how subsequent chunks of input
     * data are handled (stream-wise vs independent blocks)
     *
     * @param parser parser to use; can be left unset to either not perform
     * any parsing at all, or set it later through `setParser()`.
     *
     * @param id textual ID to associate with state for use in debug messages
     *
     * @param cid if the state is associated with one side of a
     * connection, a textual ID representing that connection.
     *
     * @param driver driver owning this state
     */
    ParsingStateForDriver(ParsingType type, const Parser* parser, std::string id, hilti::rt::Optional<std::string> cid,
                          hilti::rt::Optional<UnitContext> context, Driver* driver)
        : ParsingState(type, parser, std::move(context)),
          _id(std::move(std::move(id))),
          _cid(std::move(std::move(cid))),
          _driver(driver) {}

    /** Returns the textual ID associated with the state. */
    const auto& id() const { return _id; }

protected:
    void debug(const std::string& msg) override;

private:
    std::string _id;
    hilti::rt::Optional<std::string> _cid;
    Driver* _driver;
};

/** Connection state collecting parsing state for the two side. */
struct ConnectionState {
    std::string orig_id;
    std::string resp_id;
    ParsingStateForDriver* orig_state = nullptr;
    ParsingStateForDriver* resp_state = nullptr;
};

} // namespace driver

/** Exception thrown when a unit type is requested for parsing that isn't useable. */
HILTI_EXCEPTION(InvalidUnitType, UsageError);

/**
 * Runtime driver to retrieve and feed Spicy parsers.
 *
 * The HILTI/Spicy runtime environments must be managed externally, and must
 * have been initialized already before using any of the driver's
 * functionality.
 */
class Driver {
public:
    Driver() {}
    /**
     * Prints a human-readable list of all available parsers, retrieved from
     * the Spicy runtime system.
     *
     * @param out stream to print the summary to
     * @param verbose if true, will include alias names in output a well
     * @return an error if the list cannot be retrieved
     */
    hilti::rt::Result<hilti::rt::Nothing> listParsers(std::ostream& out, bool verbose = false);

    /**
     * Retrieves a parser by its name.
     *
     * @param name name of the parser to be retrieved, either as shown in the
     * output of `listParsers()`; or, alternatively, as a string rendering of a
     * port or MIME type as defined by a unit's properties. If no name is given
     * and there's only one parser available, that one is taken automatically.
     *
     * @param linker_scope if provided, only parsers with matching scopes are
     * considered; if omitted, the first parser with a matching name is returned,
     * independent of its scope
     *
     * @return the parser, or an error if it could not be retrieved
     *
     * \note This just forwards to `spicy::rt::lookupParser()`.
     */
    hilti::rt::Result<const spicy::rt::Parser*> lookupParser(const std::string& name = "",
                                                             const hilti::rt::Optional<uint64_t>& linker_scope = {}) {
        return spicy::rt::lookupParser(name, linker_scope);
    }

    /**
     * Feeds a parser with an input stream of data.
     *
     * @param parser parser to instantiate and feed
     * @param in stream to read input data from; will read until EOF is encountered
     * @param increment if non-zero, will feed the data in small chunks at a
     * time; this is mainly for testing parsers; incremental parsing
     *
     * @return error if the input couldn't be fed to the parser or parsing failed
     */
    hilti::rt::Result<spicy::rt::ParsedUnit> processInput(const spicy::rt::Parser& parser, std::istream& in,
                                                          int increment = 0);

    /**
     * Processes a batch of input data given in Spicy's custom batch
     * format. See the documentation of `spicy-driver` for a reference of the
     * batch format.
     *
     * @param in an open stream to read the batch from
     * @returns appropriate error if there was a problem processing the batch
     */
    hilti::rt::Result<hilti::rt::Nothing> processPreBatchedInput(std::istream& in);

    /** Records a debug message to the `spicy-driver` runtime debug stream. */
    void debug(const std::string& msg);

private:
    void _debugStats(const hilti::rt::ValueReference<hilti::rt::Stream>& data);
    void _debugStats(size_t current_flows, size_t current_connections);

    uint64_t _total_flows = 0;
    uint64_t _total_connections = 0;
};

} // namespace spicy::rt
