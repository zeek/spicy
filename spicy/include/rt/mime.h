// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <string_view>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/result.h>
#include <hilti/rt/util.h>

namespace spicy::rt {

namespace mime {

/**
 * Exception thrown by MIMEType if it cannot parse a type specification.
 */
class InvalidType : public hilti::rt::UserException {
public:
    using hilti::rt::UserException::UserException;
};
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
     * @throws `mime::InvalidType` if it cannot parse the type
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
            throw mime::InvalidType(hilti::rt::fmt("cannot parse MIME type %s", type));
    }

    MIMEType() = delete;

    /** Returns the main type, with '*' reflecting a wildcard. */
    std::string mainType() const { return _main; };

    /** Returns the sub type, with '*' reflecting a wildcard. */
    std::string subType() const { return _sub; };

    ~MIMEType() = default;
    MIMEType(const MIMEType&) = default;
    MIMEType(MIMEType&&) noexcept = default;
    MIMEType& operator=(const MIMEType&) = default;
    MIMEType& operator=(MIMEType&&) noexcept = default;

    operator std::string() const { return mainType() + "/" + subType(); }

    /**
     * Converts the type into textual key suitable for using as an index in map.
     *
     * @return If the main type is a wilcard, returns an empty string. If the
     * sub type is a wildcard, returns just the main type. Otherwise returns
     * the standard `main/sub` form.
     */
    std::string asKey() const {
        if ( _main == "*" )
            return "";

        if ( _sub == "*" )
            return _main;

        return *this;
    }

    /**
     * Parses a string `a/b` into a MIME tyoe.
     *
     * @param string of the form `main/sub`.
     * @return parsed type, or an error if not parseable
     */
    static hilti::rt::Result<MIMEType> parse(const std::string& s) {
        try {
            return MIMEType(s);
        } catch ( const mime::InvalidType& e ) {
            return hilti::rt::result::Error(e.description());
        }
    }

private:
    std::string _main; /**< Main type. */
    std::string _sub;  /**< sub type. */
};

} // namespace spicy::rt

namespace hilti::rt::detail::adl {
extern inline std::string to_string(const spicy::rt::MIMEType& x, adl::tag /*unused*/) { return x; }
} // namespace hilti::rt::detail::adl
