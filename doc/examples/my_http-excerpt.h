[...]

namespace __hlt_my_http::MyHTTP {
    struct Version;

    struct RequestLine : ::hilti::rt::trait::isStruct, ::hilti::rt::Controllable<RequestLine> {
        std::optional<::hilti::rt::Bytes> method{};
        std::optional<::hilti::rt::Bytes> uri{};
        std::optional<::hilti::rt::ValueReference<Version>> version{};
        [...]
    };

    [...]
}

namespace hlt_my_http::MyHTTP::RequestLine {
    using Type = __hlt_my_http::MyHTTP::RequestLine;

    [...]

    extern auto parse1(::hilti::rt::ValueReference<::hilti::rt::Stream>& __data, const std::optional<::hilti::rt::stream::View>& __cur, const std::optional<::spicy::rt::UnitContext>
    extern auto parse2(::hilti::rt::ValueReference<__hlt_my_http::MyHTTP::RequestLine>& __unit, ::hilti::rt::ValueReference<::hilti::rt::Stream>& __data, const std::optional<::hilt>
    extern auto parse3(::hilti::rt::ValueReference<::spicy::rt::ParsedUnit>& __gunit, ::hilti::rt::ValueReference<::hilti::rt::Stream>& __data, const std::optional<::hilti::rt::str>

    [...]
}

[...]
