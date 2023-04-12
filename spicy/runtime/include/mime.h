// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <string_view>

#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/result.h>
#include <hilti/rt/util.h>

namespace spicy::rt {

/**
 * Exception thrown by MIMEType if it cannot parse a type specification.
 */
HILTI_EXCEPTION(InvalidMIMEType, UsageError)

namespace mime {

constexpr char INVALID_NAME[] = "";

} // namespace mime

/**
 * Type representing a MIME type consisting of main type and a subtype.
 */
class MIMEType {
public:
    /**
     * Initializes a MIME type from provided main and sub type.
     *
     * @param main main type, with '*' meaning a catch-all wildcard.
     *
     * @param sub main type, with '*' meaning a catch-all wildcard.
     */
    MIMEType(std::string_view main, std::string_view sub) : _main(main), _sub(sub) {}

    /**
     * Initializes a MIME type from provided string of the form `main/sub`.
     *
     * @param mt string `main/sub`
     *
     * @throws `InvalidMIMEType` if it cannot parse the type
     */
    MIMEType(const std::string& type) {
        if ( type == "*" ) {
            _main = _sub = "*";
            return;
        }

        auto x = hilti::rt::split1(type, "/");
        _main = hilti::rt::trim(x.first);
        _sub = hilti::rt::trim(x.second);

        if ( _main.empty() || _sub.empty() )
            throw InvalidMIMEType(hilti::rt::fmt("cannot parse MIME type '%s'", type));
    }

    MIMEType() = default;

    /** Returns the main type, with '*' reflecting a wildcard. */
    std::string mainType() const {
        ensureValid();
        return _main;
    };

    /** Returns the sub type, with '*' reflecting a wildcard. */
    std::string subType() const {
        ensureValid();
        return _sub;
    };

    /** Returns true if either type or subtype is a wildcard. */
    bool isWildcard() const { return _main == "*" || _sub == "*"; }

    ~MIMEType() = default;
    MIMEType(const MIMEType&) = default;
    MIMEType(MIMEType&&) noexcept = default;
    MIMEType& operator=(const MIMEType&) = default;
    MIMEType& operator=(MIMEType&&) noexcept = default;

    operator std::string() const { return mainType() + "/" + subType(); }

    /**
     * Converts the type into textual key suitable for using as an index in map.
     *
     * @return If the main type is a wildcard, returns an empty string. If the
     * sub type is a wildcard, returns just the main type. Otherwise returns
     * the standard `main/sub` form.
     */
    std::string asKey() const {
        ensureValid();

        if ( _main == "*" )
            return "";

        if ( _sub == "*" )
            return _main;

        return *this;
    }

    /**
     * Parses a string `a/b` into a MIME type.
     *
     * @param string of the form `main/sub`.
     * @return parsed type, or an error if not parseable
     */
    static hilti::rt::Result<MIMEType> parse(const std::string& s) {
        try {
            return MIMEType(s);
        } catch ( const InvalidMIMEType& e ) {
            return hilti::rt::result::Error(e.description());
        }
    }

    friend bool operator==(const MIMEType& a, const MIMEType& b) { return a._main == b._main && a._sub == b._sub; }
    friend bool operator!=(const MIMEType& a, const MIMEType& b) { return ! (a == b); }

private:
    /** Ensure that the MIME type is valid.
     *
     * This class in general assumes that `_main` and `_sub` are valid names
     * for MIME types, but we also want this class to be default-constructible,
     * e.g., to initialize global variables. This function checks that the
     * instance was constructed with valid `_main` and `_sub`.
     *
     * @throw `InvalidType` if the instance was not initialized with a proper type
     */
    void ensureValid() const {
        if ( _main == mime::INVALID_NAME || _sub == mime::INVALID_NAME )
            throw InvalidMIMEType("MIME type is uninitialized");
    }

    std::string _main = mime::INVALID_NAME; /**< Main type. */
    std::string _sub = mime::INVALID_NAME;  /**< sub type. */
};

} // namespace spicy::rt

namespace hilti::rt::detail::adl {
extern inline std::string to_string(const spicy::rt::MIMEType& x, adl::tag /*unused*/) { return x; }
} // namespace hilti::rt::detail::adl
