[...]

namespace __hlt::MyHTTP {
    struct RequestLine : hilti::rt::trait::isStruct, hilti::rt::Controllable<RequestLine> {
        std::optional<hilti::rt::Bytes> method{};
        std::optional<hilti::rt::Bytes> uri{};
        std::optional<hilti::rt::ValueReference<Version>> version{};
        [...]
    };

    struct Version : hilti::rt::trait::isStruct, hilti::rt::Controllable<Version> {
        std::optional<hilti::rt::Bytes> number{};
        [...]
    };

[...]
}

namespace hlt::MyHTTP::RequestLine {
    extern auto parse1(hilti::rt::ValueReference<hilti::rt::Stream>& data, const std::optional<hilti::rt::stream::View>& cur) -> hilti::rt::Resumable;
    extern auto parse2(hilti::rt::ValueReference<__hlt::MyHTTP::RequestLine>& unit, hilti::rt::ValueReference<hilti::rt::Stream>& data, const std::optional<hilti::rt::stream::View>& cur) -> hilti::rt::Resumable;
    extern auto parse3(spicy::rt::ParsedUnit& gunit, hilti::rt::ValueReference<hilti::rt::Stream>& data, const std::optional<hilti::rt::stream::View>& cur) -> hilti::rt::Resumable;
}

[...]
