// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.


#include <doctest/doctest.h>

#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/bool.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes;
using namespace hilti::rt::bytes::literals;
using namespace hilti::rt::stream;
using hilti::rt::to_string;

TEST_SUITE_BEGIN("Stream");

auto make_stream(std::initializer_list<Bytes> xs) {
    Stream s;
    for ( auto&& x : xs )
        s.append(x);

    return s;
}

TEST_CASE("size") {
    CHECK_EQ(make_stream({}).size(), 0U);
    CHECK_EQ(make_stream({"123\x00"_b}).size(), 4U);
    CHECK_EQ(make_stream({"12"_b, "3\x00"_b}).size(), 4U);
}

TEST_CASE("isEmpty") {
    CHECK(Stream().isEmpty());
    CHECK_FALSE(Stream("123"_b).isEmpty());
    CHECK_FALSE(Stream("\x00"_b).isEmpty());
}

TEST_CASE("construct") {
    SUBCASE("small") {
        auto x = Stream("xyz"_b);
        CHECK_EQ(to_string(x), R"(b"xyz")");
        CHECK_FALSE(x.isEmpty());
        CHECK_EQ(x.size().Ref(), 3);
        CHECK_EQ(x.numberOfChunks(), 1);
    }

    SUBCASE("big") {
        auto y = Stream("123456789012345678901234567890123"_b); // Exceeds small buffer size.
        CHECK_FALSE(y.isEmpty());
        CHECK_EQ(y.size().Ref(), 33);
        CHECK_EQ(y.numberOfChunks(), 1);
        CHECK_EQ(to_string(y), R"(b"123456789012345678901234567890123")");
    }

    SUBCASE("empty") {
        auto x = Stream(""_b);
        CHECK_EQ(to_string(x), R"(b"")");
        CHECK(x.isEmpty());
        CHECK_EQ(x.size().Ref(), 0);
        CHECK(x.statistics() == stream::Statistics());
    }

    SUBCASE("from small") {
        auto x = Stream("xyz"_b);
        auto z = x;
        CHECK_EQ(to_string(z), R"(b"xyz")");
        CHECK_FALSE(z.isEmpty());
        CHECK_EQ(z.size().Ref(), 3);
        CHECK_EQ(x.statistics().num_data_bytes, 3);
        CHECK_EQ(x.statistics().num_data_chunks, 1);
    }

    SUBCASE("from big") {
        auto y = Stream("123456789012345678901234567890123"_b); // Exceeds small buffer size.
        auto z = y;
        CHECK_EQ(to_string(z), R"(b"123456789012345678901234567890123")");
        CHECK_FALSE(z.isEmpty());
        CHECK_EQ(z.size().Ref(), 33);
        CHECK_EQ(y.statistics().num_data_bytes, 33);
        CHECK_EQ(y.statistics().num_data_chunks, 1);
    }

    SUBCASE("from empty") {
        auto m = Stream();
        m = Stream(""_b);
        CHECK_EQ(to_string(m), R"(b"")");
        CHECK(m.isEmpty());
        CHECK_EQ(m.size().Ref(), 0);
        CHECK_EQ(m.statistics().num_data_bytes, 0);
        CHECK_EQ(m.statistics().num_data_chunks, 0);
    }

    SUBCASE("unfrozen") {
        auto x = Stream("foo"_b);
        CHECK_FALSE(x.isFrozen());
        x.freeze();
        CHECK(x.isFrozen());
    }

    SUBCASE("from memory block") {
        auto xs = "123"_b;
        const auto s = Stream(xs.data(), xs.size());
        CHECK_EQ(s, Stream("123"_b));
        // Underlying data is copied.
        xs = "456"_b;
        CHECK_EQ(s, Stream("123"_b));
    }

    SUBCASE("from rvalue") {
        auto s = Stream("123"_b);
        CHECK_EQ(Stream(std::move(s)), Stream("123"_b));
    }

    SUBCASE("from Bytes") {
        auto d1 = Bytes(1, '\x01');
        CHECK_EQ(to_string_for_print(Stream(d1)), escapeBytes(d1.str(), render_style::Bytes::EscapeQuotes));

        auto d2 = Bytes(1024, '\x01');
        CHECK_EQ(to_string_for_print(Stream(d2)), escapeBytes(d2.str(), render_style::Bytes::EscapeQuotes));
    }
}

TEST_CASE("assign") {
    SUBCASE("from lvalue") {
        auto x = Stream("1234"_b);
        auto y = Stream("abc"_b);
        auto it = y.begin();
        REQUIRE_NOTHROW(*it);

        y = x;
        CHECK_EQ(y, x);
        CHECK_THROWS_WITH_AS(*it, "stream object no longer available", const InvalidIterator&);
        CHECK_EQ(y.statistics().num_data_bytes, 4);
    }

    SUBCASE("multiple chunks") {
        // This test is value-parameterized over these values.
        Stream x;
        Stream y;

        SUBCASE("both chunked") {
            x = make_stream({"12"_b, "34"_b});
            y = make_stream({"ab"_b, "cd"_b});

            CHECK_EQ(x.statistics().num_data_bytes, 4);
            CHECK_EQ(x.statistics().num_data_bytes, 4);
        }

        SUBCASE("LHS chunked") {
            x = make_stream({"1234"_b});
            y = make_stream({"ab"_b, "cd"_b});
        }

        SUBCASE("RHS chunked") {
            x = make_stream({"12"_b, "34"_b});
            y = make_stream({"abcd"_b});
        }

        REQUIRE_EQ(to_string_for_print(y), "abcd");

        y = x;
        CHECK_EQ(to_string_for_print(y), "1234");
    }

    SUBCASE("self-assign") { // Self-assignment is a no-op.
        auto s = Stream("123"_b);

        *&s = s; // Assign through a pointer to not trigger compiler warnings about self-assignments.
        CHECK_EQ(s, Stream("123"_b));

        *&s = std::move(s); // Assign through a pointer to not trigger compiler warnings about self-assignments.
        // NOLINTNEXTLINE(bugprone-use-after-move)
        CHECK_EQ(s, Stream("123"_b));
    }
}

TEST_CASE("equal") {
    const auto b1 = "123"_b;
    const auto b2 = "abc"_b;
    const auto b_ = ""_b;

    const auto s1 = Stream(b1);
    const auto s2 = Stream(b2);
    const auto s_ = Stream();

    SUBCASE("Stream") {
        CHECK_EQ(s1, s1);
        CHECK_EQ(s1, Stream(s1));
        CHECK_EQ(make_stream({"12"_b, "34"_b}), make_stream({"12"_b, "34"_b}));
        CHECK_EQ(make_stream({"1234"_b}), make_stream({"12"_b, "34"_b}));
        CHECK_NE(make_stream({"12"_b, "cd"_b}), make_stream({"12"_b, "34"_b}));
        CHECK_EQ(s_, s_);
        CHECK_NE(s1, s_);
        CHECK_NE(s1, s2);
    }

    SUBCASE("Bytes") {
        CHECK_EQ(s1, b1);
        CHECK_EQ(make_stream({"12"_b, "34"_b}), "1234"_b);
        CHECK_NE(s1, b2);
        CHECK_NE(s1, b_);
    }

    SUBCASE("View") {
        CHECK_EQ(s1, s1.view());
        CHECK_EQ(s1, s1.view(true));
        CHECK_EQ(s1, s1.view(false));
        CHECK_EQ(s1, Stream(s1).view());
        CHECK_NE(s1, s2.view());
        CHECK_NE(s1, s_.view());

        {
            auto s = make_stream({"12"_b, "34"_b});
            CHECK_EQ(s, s.view(true));
            CHECK_EQ(s, s.view(false));
        }
    }
}

TEST_CASE("append") {
    auto s = Stream("123"_b);

    const auto empty = ""_b;
    const auto xs = "456"_b;

    REQUIRE_EQ(s.size(), 3);
    REQUIRE_EQ(s.numberOfChunks(), 1);

    SUBCASE("lvalue Bytes") {
        s.append(empty);
        CHECK_EQ(s, "123"_b);
        CHECK_EQ(s.size(), 3);
        CHECK_EQ(s.numberOfChunks(), 1);

        s.append(xs);
        CHECK_EQ(s, "123456"_b);
        CHECK_EQ(s.size(), 6);
        CHECK_EQ(s.numberOfChunks(), 2);

        s.freeze();
        CHECK_NOTHROW(s.append(empty));
        CHECK_THROWS_WITH_AS(s.append(xs), "stream object can no longer be modified", const Frozen&);

        CHECK_EQ(s.statistics().num_data_bytes, 6);
        CHECK_EQ(s.statistics().num_data_chunks, 2);
    }

    SUBCASE("rvalue Bytes") {
        s.append(empty);
        CHECK_EQ(s, "123"_b);
        CHECK_EQ(s.size(), 3);
        CHECK_EQ(s.numberOfChunks(), 1);

        s.append(xs);
        CHECK_EQ(s, "123456"_b);
        CHECK_EQ(s.size(), 6);
        CHECK_EQ(s.numberOfChunks(), 2);

        s.freeze();
        CHECK_NOTHROW(s.append(""_b));
        CHECK_THROWS_WITH_AS(s.append("456"_b), "stream object can no longer be modified", const Frozen&);

        CHECK_EQ(s.statistics().num_data_bytes, 6);
        CHECK_EQ(s.statistics().num_data_chunks, 2);
    }

    SUBCASE("raw memory") {
        const char* data = "456";

        s.append(data, 0);
        CHECK_EQ(s, "123"_b);
        CHECK_EQ(s.size(), 3);
        CHECK_EQ(s.numberOfChunks(), 1);

        s.append(data, strlen(data));
        CHECK_EQ(s, "123456"_b);
        CHECK_EQ(s.size(), 6);
        CHECK_EQ(s.numberOfChunks(), 2);

        s.freeze();
        CHECK_NOTHROW(s.append(data, 0));
        CHECK_THROWS_WITH_AS(s.append(data, strlen(data)), "stream object can no longer be modified", const Frozen&);

        CHECK_EQ(s.statistics().num_data_bytes, 6);
        CHECK_EQ(s.statistics().num_data_chunks, 2);
    }
}

TEST_CASE("iteration") {
    SUBCASE("sees data") {
        // This test is value-parameterized over `x`.
        Stream x;

        SUBCASE("single chunk") { x = make_stream({"12345"_b}); }
        SUBCASE("multiple chunks") { x = make_stream({"12"_b, "34"_b, "5"_b}); }

        std::string s;
        for ( auto i : x )
            s += static_cast<std::string::value_type>(i);

        CHECK_EQ(s, "12345");
    }

    SUBCASE("see data updates") {
        auto x = Stream("12345"_b);
        x.append("1234567890"_b);
        x.append("1234567890"_b);
        x.append("1234567890"_b);
        x.append("1234567890"_b);

        std::string s;
        for ( auto i : x )
            s += static_cast<std::string::value_type>(i);

        CHECK_EQ(s, "123451234567890123456789012345678901234567890");
    }

    SUBCASE("equality") {
        SUBCASE("unchanged stream") {
            // This test is value-parameterized over `x`.
            Stream x;

            SUBCASE("single chunk") { x = make_stream({"1234512345678901"_b}); }
            SUBCASE("multiple chunks") {
                x = make_stream({"12"_b, "34"_b, "51"_b, "23"_b, "45"_b, "67"_b, "89"_b, "01"_b});
            }

            auto i = x.begin();
            i += 7;
            CHECK_EQ(*i, '3');
            i += 7;
            CHECK_EQ(*i, '0');
            i += 1;
            CHECK_EQ(*i, '1');
        }

        SUBCASE("updated stream") {
            // This test is value-parameterized over `x`.
            Stream x;

            SUBCASE("single chunk") { x = make_stream({"123"_b}); }
            SUBCASE("multiple chunks") { x = make_stream({"1"_b, "2"_b, "3"_b}); }

            const auto i = x.begin();
            auto j = x.end();
            CHECK_NE(j, i);
            CHECK_EQ(j, x.end());

            x.append("abc"_b);
            CHECK_NE(j, x.end());
            CHECK_EQ(*j, 'a');

            ++j;
            CHECK_NE(j, x.end());
            ++j;
            CHECK_NE(j, x.end());
            ++j;
            CHECK_EQ(j, x.end());
        }
    }

    SUBCASE("rangecheck") {
        // This test is value-parameterized over `x`.
        Stream x;

        SUBCASE("single chunk") { x = make_stream({"123"_b}); }
        SUBCASE("multiple chunks") { x = make_stream({"1"_b, "2"_b, "3"_b}); }

        auto i = x.begin();

        i += 3; // Points beyond the end of the available data.
        CHECK_THROWS_AS(*i, InvalidIterator);

        x.append("456"_b);
        CHECK_EQ(*i, '4'); // Enough data available now.
    }

    SUBCASE("lifetime bound by underlying stream") {
        auto j = Stream().begin();
        CHECK_THROWS_AS((void)(*j == '6'), InvalidIterator); // j now invalid.
    }

    SUBCASE("invariant when data added") {
        auto s = Stream("0123"_b);
        auto i0 = s.begin();
        auto i1 = i0 + 1;
        REQUIRE_EQ(*i0, '0');
        REQUIRE_EQ(*i1, '1');

        s.append("456789"_b);

        CHECK_EQ(*i0, '0');
        CHECK_EQ(*i1, '1');
    }

    SUBCASE("difference") {
        const auto x = []() {
            auto s = Stream(" 123"_b);
            const auto before_begin = s.begin();

            s.trim(before_begin + 1);
            REQUIRE_EQ(s, "123"_b);

            return tuple::make(std::move(s), before_begin);
        }();
        const auto& s = tuple::get<0>(x);
        const auto& before_begin = tuple::get<1>(x);

        REQUIRE_FALSE(before_begin.isExpired());

        const auto begin = s.begin();
        const auto middle = begin + 1;
        const auto end = s.end();
        const auto past_end = end + 2;

        CHECK_GT(begin, before_begin);
        CHECK_LT(begin, middle);
        CHECK_LT(begin, end);
        CHECK_LT(begin, past_end);

        CHECK_EQ(begin - before_begin, 1);
        CHECK_EQ(begin - middle, -1);
        CHECK_EQ(begin - end, -3);
        CHECK_EQ(begin - past_end, -5);

        CHECK_GT(middle, before_begin);
        CHECK_GT(middle, begin);
        CHECK_LT(middle, end);
        CHECK_LT(middle, past_end);

        CHECK_EQ(middle - before_begin, 2);
        CHECK_EQ(middle - begin, 1);
        CHECK_EQ(middle - end, -2);
        CHECK_EQ(middle - past_end, -4);

        CHECK_GT(end, before_begin);
        CHECK_GT(end, begin);
        CHECK_GT(end, middle);
        CHECK_LT(end, past_end);

        CHECK_EQ(end - before_begin, 4);
        CHECK_EQ(end - begin, 3);
        CHECK_EQ(end - middle, 2);
        CHECK_EQ(end - past_end, -2);

        CHECK_GT(past_end, before_begin);
        CHECK_GT(past_end, begin);
        CHECK_GT(past_end, middle);
        CHECK_GT(past_end, end);

        CHECK_EQ(past_end - before_begin, 6);
        CHECK_EQ(past_end - begin, 5);
        CHECK_EQ(past_end - middle, 4);
        CHECK_EQ(past_end - end, 2);
    }

    SUBCASE("ordering") {
        // This test is value-parameterized over `s`.
        Stream s;

        SUBCASE("single chunk") { s = make_stream({"123"_b}); }
        SUBCASE("multiple chunks") { s = make_stream({"1"_b, "2"_b, "3"_b}); }

        CHECK_LE(s.begin(), s.begin());
        CHECK_LE(s.begin(), s.end());
        CHECK_LT(s.begin(), s.end());

        CHECK_GE(s.begin(), s.begin());
        CHECK_GE(s.end(), s.begin());
        CHECK_GT(s.end(), s.begin());
    }

    SUBCASE("increment") {
        // This test is value-parameterized over `s`.
        Stream s;

        SUBCASE("single chunk") { s = make_stream({"123"_b}); }
        SUBCASE("multiple chunks") { s = make_stream({"1"_b, "2"_b, "3"_b}); }

        auto it = s.begin();
        REQUIRE_EQ(*it, '1');

        CHECK_EQ(*(it++), '1');
        CHECK_EQ(*it, '2');
        CHECK_EQ(*(++it), '3');
        CHECK_EQ(*it, '3');
    }

    SUBCASE("increment - regression test for #1918") {
        auto s = make_stream({"123"_b});
        // Add two more chunks, with the 1st larger than the existing one. This
        // will let the trim later destroy the original chunk, instead of
        // continuing to cache it internally.
        s.append("4567"_b);
        s.append("890"_b);

        auto i = s.begin();
        s.trim(i + 4);
        s.trim(i + 7);
        i = i + 7; // triggered ASAN heap-use-after-free before fixing #1918
    }

    SUBCASE("decrement - SafeIterator") {
        // This test is value-parameterized over `s`.
        Stream s;

        SUBCASE("single chunk") { s = make_stream({"123"_b}); }
        SUBCASE("multiple chunks") { s = make_stream({"1"_b, "2"_b, "3"_b}); }

        auto it = s.end();
        REQUIRE_EQ(*(--it), '3');
        REQUIRE_EQ(*(--it), '2');
        REQUIRE_EQ(*(--it), '1');
        REQUIRE_EQ(it, s.begin());

        CHECK_THROWS_AS(--it, const InvalidIterator&);

        it = s.end() - 2;
        REQUIRE_EQ(*it, '2');

        it = s.end();
        it -= 2;
        REQUIRE_EQ(*it, '2');

        it = s.end();
        CHECK_THROWS_AS((it -= 100), const InvalidIterator&);
    }

    SUBCASE("decrement - regression test for #1918") {
        auto s = make_stream({"123"_b});
        // Add two more chunks, with the 1st smaller than the existing one.
        // This will let the trim later destroy this added chunk, instead of
        // continuing to cache it internally.
        s.append("45"_b);
        s.append("678"_b);

        auto i = s.begin() + 4;
        s.trim(i);
        s.trim(i + 3);
        i = i - 4; // triggered ASAN heap-use-after-free before fixing #1918
    }

    SUBCASE("decrement - UnsafeIterator") {
        // This test is value-parameterized over `s`.
        Stream s;

        SUBCASE("single chunk") { s = make_stream({"123"_b}); }
        SUBCASE("multiple chunks") { s = make_stream({"1"_b, "2"_b, "3"_b}); }

        auto it = s.unsafeEnd();
        REQUIRE_EQ(*(--it), '3');
        REQUIRE_EQ(*(--it), '2');
        REQUIRE_EQ(*(--it), '1');
        REQUIRE_EQ(it, s.unsafeBegin());

        it = s.unsafeEnd() - 2;
        REQUIRE_EQ(*it, '2');

        it = s.unsafeEnd();
        it -= 2;
        REQUIRE_EQ(*it, '2');

        // not testing underflow, won't be caught with unsafe version
    }

    SUBCASE("bool") {
        CHECK_FALSE(stream::SafeConstIterator());
        CHECK(Stream().begin());
        CHECK(Stream().end());
        CHECK(Stream("123"_b).begin());
        CHECK(Stream("123"_b).end());
    }

    SUBCASE("isUnset") {
        CHECK(stream::SafeConstIterator().isUnset());
        CHECK_FALSE(Stream().begin().isUnset());
    }

    SUBCASE("isEnd") {
        CHECK(stream::SafeConstIterator().isEnd());
        CHECK(Stream().begin().isEnd());
        CHECK(Stream().end().isEnd());
        CHECK_FALSE(Stream("123"_b).begin().isEnd());
        CHECK(Stream("123"_b).end().isEnd());

        {
            auto s = Stream("123"_b);
            auto it1 = s.end();
            auto it2 = it1 + 1;
            REQUIRE(it1.isEnd());
            REQUIRE(it2.isEnd());

            s.append("4"_b);

            REQUIRE_FALSE(it1.isEnd());
            REQUIRE(it2.isEnd());
        }
    }

    SUBCASE("isExpired") {
        auto it = stream::SafeConstIterator();
        CHECK_FALSE(stream::SafeConstIterator().isExpired());

        {
            auto s = Stream("123"_b);
            it = s.begin();
            CHECK_FALSE(it.isExpired());
        }

        CHECK(it.isExpired());
    }

    SUBCASE("dereference") {
        CHECK_THROWS_WITH_AS(*stream::SafeConstIterator(), "unbound stream iterator", const InvalidIterator&);
        CHECK_THROWS_WITH_AS(*Stream().begin(), "stream iterator outside of valid range", const InvalidIterator&);

        auto s = Stream("123");
        REQUIRE_FALSE(s.isEmpty());

        const auto begin = s.begin();
        const auto end = s.end();
        CHECK_EQ(*begin, '1');
        CHECK_THROWS_WITH_AS(*end, "stream iterator outside of valid range", const InvalidIterator&);

        s.trim(end);
        REQUIRE(s.isEmpty());
        CHECK_THROWS_WITH_AS(*begin, "stream iterator outside of valid range", const InvalidIterator&);
        CHECK_THROWS_WITH_AS(*end, "stream iterator outside of valid range", const InvalidIterator&);
    }
}

TEST_CASE("sub") {
    auto x = Stream("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);

    auto i = (x.begin() + 5);
    auto j = (x.begin() + 15);

    CHECK_EQ(x.view().sub(i, j), "6789012345"_b);

    auto y = Stream("12345"_b);
    CHECK_EQ(y.view().sub(y.begin(), y.end()), "12345"_b);
    CHECK_EQ(y.view().sub(y.begin(), y.begin()), ""_b);
    CHECK_EQ(y.view().sub(y.end(), y.end()), ""_b);

    auto f = [](const stream::View& v) { return v.sub(v.begin() + 15, v.begin() + 25); };

    CHECK_EQ(to_string(f(x.view())), R"(b"6789012345")");
}

TEST_CASE("freezing") {
    auto x = Stream("12345"_b);
    x.append("123456789A"_b);
    x.append("B234567890"_b);
    x.append("1234567890"_b);
    x.append("123456789D"_b);
    x.append("E234567890"_b);

    auto i = (x.begin() + 25);
    CHECK_FALSE(i.isFrozen());
    x.freeze();
    CHECK(i.isFrozen());
    x.unfreeze();
    CHECK_FALSE(i.isFrozen());
}

TEST_CASE("convert view to stream") {
    auto x = Stream("12345"_b);
    auto v = stream::View(x.begin() + 1, x.begin() + 3);
    CHECK(v == "23"_b);
    auto y = Stream(v);
    CHECK(y == "23"_b);

    x.append("ABCDEF"_b);
    x.append("GHJI"_b);
    v = stream::View(x.begin() + 1, x.begin() + 12);
    CHECK_EQ(v, "2345ABCDEFG"_b);
    y = Stream(v);
    CHECK_EQ(y, "2345ABCDEFG"_b);

    CHECK_EQ(y.statistics().num_data_bytes, 11);
    CHECK_EQ(y.statistics().num_data_chunks, 1);
}

TEST_CASE("Expanding vs non-expanding views") {
    auto x = Stream("12345"_b);
    auto v1 = x.view(true);  // expanding
    auto v2 = x.view(false); // non-expanding
    x.append("123456789A"_b);
    x.append("B234567890"_b);
    x.append("1234567890"_b);
    x.append("123456789D"_b);
    x.append("E234567890"_b);

    CHECK_EQ(v1.size().Ref(), 55);
    CHECK_EQ(v2.size().Ref(), 5);
}

TEST_CASE("Trim") {
    auto x = Stream("12345678901234567890123456789012"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);

    auto y = x;

    CHECK_EQ(x.size().Ref(), 72);
    CHECK_EQ(x.numberOfChunks(), 5);

    x.trim(x.at(10));
    CHECK_EQ(x.size().Ref(), 62);
    x.trim(x.at(20));
    CHECK_EQ(x.begin().offset().Ref(), 20);
    CHECK_EQ(x.size().Ref(), 52);
    x.trim(x.at(32));
    CHECK_EQ(x.size().Ref(), 40);
    CHECK_EQ(x.numberOfChunks(), 4);
    x.trim(x.at(50));
    CHECK_EQ(x.size().Ref(), 22);
    CHECK_EQ(x.numberOfChunks(), 3);
    x.trim(x.at(65));
    CHECK_EQ(x.begin().offset().Ref(), 65);
    CHECK_EQ(x.size().Ref(), 7);
    CHECK_EQ(x, "4567890"_b);
    CHECK_EQ(x.numberOfChunks(), 1);
    x.trim(x.at(72));
    CHECK_EQ(x.size().Ref(), 0);
    CHECK_EQ(x, ""_b);
    CHECK_EQ(x.numberOfChunks(), 0);
    CHECK_EQ(x.begin().offset().Ref(), 72);

    y.trim(y.at(100));
    CHECK_EQ(y.size().Ref(), 0);
    CHECK_EQ(y.begin().offset().Ref(), 100);

    auto z = Stream("12345"_b);
    z.trim(z.at(3));
    CHECK_EQ(z, "45"_b);
    CHECK_EQ(z.size().Ref(), 2);
    z.trim(z.at(5));
    CHECK_EQ(z, ""_b);
    CHECK_EQ(z.size().Ref(), 0);

    // Statistics aren't affected by trimming.
    CHECK_EQ(x.statistics().num_data_bytes, 72);
    CHECK_EQ(x.statistics().num_data_chunks, 5);
}

TEST_CASE("Trim with existing iterator and append") {
    auto x = Stream("01"_b);
    auto i = x.begin();
    auto j = x.begin();

    i += 3;
    x.append("2345"_b);
    j += 2;
    x.trim(j);
    CHECK_EQ(*i, '3');
}

TEST_CASE("Trim with existing beyond-end iterator and append") {
    auto x = Stream("01"_b);
    const auto i = x.begin() + 10;
    const auto j = x.begin() + 2;

    x.trim(j);
    x.append("23456789ab"_b);
    CHECK_EQ(*i, 'a');
}

TEST_CASE("Trim to beyond end") {
    auto x = Stream("01"_b);
    auto i = x.begin();
    i += 5;
    x.trim(i);
    CHECK_EQ(x.numberOfChunks(), 0);
    CHECK_EQ(x, ""_b);
    x.append("56789");
    CHECK_EQ(*i, '5');
    CHECK_EQ(x.view().begin().offset(), 5);
    CHECK_EQ(x.view().end().offset(), 10);
}

TEST_CASE("Trim noop") {
    auto x = Stream("1"_b);
    auto i = x.begin(); // Into first chunk.

    x.append("2"_b);
    REQUIRE_EQ(x.numberOfChunks(), 2);

    auto j = x.begin() + x.size() - 1; // Into second chunk.

    x.trim(j); // Drops the first chunk.
    CHECK_EQ(x.numberOfChunks(), 1);

    // Trimming away data before the range of the stream should be a noop.
    x.trim(i);
    CHECK_EQ(x.numberOfChunks(), 1);
}

TEST_CASE("Trim empty") {
    auto x = Stream();
    REQUIRE_EQ(x.numberOfChunks(), 0);

    auto i = x.begin();

    x.trim(i);
    CHECK_EQ(x.numberOfChunks(), 0);
}

TEST_CASE("Block iteration") {
    auto content = [](auto b, auto s) -> bool { return memcmp(b->start, s, strlen(s)) == 0; };

    auto x = Stream("01234"_b);

    auto v = x.view();
    auto block = v.firstBlock();
    CHECK(block);
    CHECK(content(block, "01234"));
    CHECK_EQ(block->offset, 0);
    CHECK_EQ(block->size, 5);
    CHECK(block->is_first);
    CHECK(block->is_last);
    CHECK_FALSE(v.nextBlock(block));

    x.append("567"_b);
    x.append("890"_b);
    x.append("abc"_b);
    x.append("def"_b);

    v = x.view();
    block = v.firstBlock();
    CHECK(block);
    CHECK(content(block, "01234"));
    CHECK_EQ(block->offset, 0);
    CHECK_EQ(block->size, 5);
    CHECK(block->is_first);
    CHECK_FALSE(block->is_last);
    block = v.nextBlock(block);
    CHECK(block);
    CHECK(content(block, "567"));
    CHECK_EQ(block->offset, 5);
    CHECK_EQ(block->size, 3);
    CHECK_FALSE(block->is_first);
    CHECK_FALSE(block->is_last);
    block = v.nextBlock(block);
    CHECK(block);
    CHECK(content(block, "890"));
    CHECK_EQ(block->offset, 8);
    CHECK_EQ(block->size, 3);
    CHECK_FALSE(block->is_first);
    CHECK_FALSE(block->is_last);
    block = v.nextBlock(block);
    CHECK(block);
    CHECK(content(block, "abc"));
    CHECK_EQ(block->offset, 11);
    CHECK_EQ(block->size, 3);
    CHECK_FALSE(block->is_first);
    CHECK_FALSE(block->is_last);
    block = v.nextBlock(block);
    CHECK(block);
    CHECK(content(block, "def"));
    CHECK_EQ(block->offset, 14);
    CHECK_EQ(block->size, 3);
    CHECK_FALSE(block->is_first);
    CHECK(block->is_last);
    CHECK_FALSE(v.nextBlock(block));

    v = v.sub(v.at(6), v.at(13));
    block = v.firstBlock();
    CHECK(block);
    CHECK(content(block, "67"));
    CHECK_EQ(block->offset, 6);
    CHECK_EQ(block->size, 2);
    CHECK(block->is_first);
    CHECK_FALSE(block->is_last);
    block = v.nextBlock(block);
    CHECK(block);
    CHECK(content(block, "890"));
    CHECK_EQ(block->offset, 8);
    CHECK_EQ(block->size, 3);
    CHECK_FALSE(block->is_first);
    CHECK_FALSE(block->is_last);
    block = v.nextBlock(block);
    CHECK(block);
    CHECK(content(block, "ab"));
    CHECK_EQ(block->offset, 11);
    CHECK_EQ(block->size, 2);
    CHECK_FALSE(block->is_first);
    CHECK(block->is_last);
    CHECK_FALSE(v.nextBlock(block));
}

TEST_CASE("to_string") {
    // Stream data should be rendered like the underlying `Bytes`.
    const auto bytes = "ABC"_b;
    const auto stream = Stream(bytes);
    const auto view = stream.view();
    REQUIRE_EQ(to_string(stream), to_string(bytes));
    REQUIRE_EQ(to_string(view), to_string(bytes));
    CHECK_EQ(to_string(stream.begin()), fmt("<offset=0 data=%s>", to_string(bytes)));
}

template<typename T, int N>
std::vector<T> vec(T (&xs)[N]) {
    std::vector<T> ys;
    ys.assign(xs, xs + N);
    return ys;
}

TEST_CASE("View") {
    SUBCASE("advance") {
        auto input = "1234567890"_b;
        auto stream = Stream(input);
        auto view = stream.view();

        REQUIRE_EQ(view.size(), input.size());

        auto advance = 5;
        view = view.advance(advance);

        CHECK_EQ(view.size(), input.size() - advance);
        CHECK(view.startsWith("67890"_b));
    }

    SUBCASE("advanceToNextData") {
        auto stream = Stream();
        stream.append("A");
        stream.append(nullptr, 1024);
        stream.append("BC");

        std::optional<View> view;
        SUBCASE("view with zero offset") { view = stream.view(); }

        SUBCASE("with with non-zero offset") {
            // This is a regression test for GH-1303.
            view = stream.view().sub(1, stream.end().offset() + 1);
        }

        REQUIRE(view);

        auto ncur = view->advanceToNextData();
        CHECK_EQ(ncur.offset(), 1025);
        CHECK_EQ(ncur.data().str(), "BC");
    }

    SUBCASE("dataForPrint") {
        auto s = make_stream({"AAA", "BBB", "CCC"});
        REQUIRE_EQ(s.numberOfChunks(), 3);

        auto v = s.view();

        // `start` and `end` at chunk boundary.
        CHECK_EQ(v.dataForPrint(), "AAABBBCCC");
        CHECK_EQ(v.sub(v.begin(), v.end()).dataForPrint(), "AAABBBCCC");
        CHECK_EQ(v.sub(v.begin() + 3, v.end()).dataForPrint(), "BBBCCC");
        CHECK_EQ(v.sub(v.begin(), v.end() - 3).dataForPrint(), "AAABBB");
        CHECK_EQ(v.sub(v.begin() + 3, v.end() - 3).dataForPrint(), "BBB");

        // `start` or `end` inside different chunks.
        CHECK_EQ(v.sub(v.begin() + 1, v.end()).dataForPrint(), "AABBBCCC");
        CHECK_EQ(v.sub(v.begin(), v.end() - 1).dataForPrint(), "AAABBBCC");
        CHECK_EQ(v.sub(v.begin() + 1, v.end() - 1).dataForPrint(), "AABBBCC");

        // `start` and `end` inside same chunk.
        CHECK_EQ(v.sub(v.begin() + 1, v.begin() + 1).dataForPrint(), "");
        CHECK_EQ(v.sub(v.begin() + 1, v.begin() + 2).dataForPrint(), "A");
        CHECK_EQ(v.sub(v.begin() + 4, v.begin() + 5).dataForPrint(), "B");
        CHECK_EQ(v.sub(v.begin() + 7, v.begin() + 8).dataForPrint(), "C");
    }

    SUBCASE("dataForPrint with gap chunks") {
        auto s = Stream();
        s.append("AAA");
        s.append(nullptr, 3);
        s.append("CCC");
        REQUIRE_EQ(s.numberOfChunks(), 3);

        CHECK_EQ(s.statistics().num_data_bytes, 6);
        CHECK_EQ(s.statistics().num_data_chunks, 2);
        CHECK_EQ(s.statistics().num_gap_bytes, 3);
        CHECK_EQ(s.statistics().num_gap_chunks, 1);

        auto v = s.view();
        CHECK_EQ(v.dataForPrint(), "AAA<gap>CCC");

        CHECK_EQ(v.sub(v.begin() + 3, v.end()).dataForPrint(), "<gap>CCC");
        CHECK_EQ(v.sub(v.begin() + 4, v.end()).dataForPrint(), "<gap>CCC");
        CHECK_EQ(v.sub(v.begin() + 5, v.end()).dataForPrint(), "<gap>CCC");

        CHECK_EQ(v.sub(v.begin() + 3, v.begin() + 6).dataForPrint(), "<gap>");
        CHECK_EQ(v.sub(v.begin() + 3, v.begin() + 5).dataForPrint(), "<gap>");
        CHECK_EQ(v.sub(v.begin() + 3, v.begin() + 4).dataForPrint(), "<gap>");

        CHECK_EQ(v.sub(v.begin() + 3, v.begin() + 3).dataForPrint(), "");

        CHECK_EQ(v.sub(v.begin() + 6, v.end()).dataForPrint(), "CCC");
    }

    SUBCASE("equal") {
        const auto b1 = "123"_b;
        const auto b2 = "abc"_b;
        const auto b_ = ""_b;

        const auto s1 = Stream(b1);
        const auto s2 = Stream(b2);
        const auto s_ = Stream(b_);

        const auto v1 = s1.view();
        const auto v2 = s2.view();
        const auto v_ = s_.view();

        SUBCASE("Bytes") {
            CHECK_EQ(v1, b1);
            CHECK_EQ(v_, b_);
            CHECK_NE(v1, b2);
        }

        SUBCASE("Stream") {
            CHECK_EQ(v1, s1);
            CHECK_EQ(v_, s_);
            CHECK_NE(v1, s2);
        }

        SUBCASE("View") {
            CHECK_EQ(v1, v1);
            CHECK_EQ(v_, v_);
            CHECK_NE(v1, v2);
        }
    }

    SUBCASE("extract") {
        auto s = Stream("1234567890"_b);
        const auto v = s.view();

        SUBCASE("1") {
            Byte dst[1] = {'0'};
            CHECK_EQ(v.extract(dst, sizeof(dst)), "234567890"_b);
            CHECK_EQ(vec(dst), std::vector<Byte>({'1'}));
        }

        SUBCASE("3") {
            Byte dst[3] = {'0'};
            CHECK_EQ(v.extract(dst, sizeof(dst)), "4567890"_b);
            CHECK_EQ(vec(dst), std::vector<Byte>({'1', '2', '3'}));
        }

        SUBCASE("all") {
            Byte dst[10] = {'0'};
            CHECK_EQ(v.extract(dst, sizeof(dst)), ""_b);
            CHECK_EQ(vec(dst), std::vector<Byte>({'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}));
        }

        SUBCASE("empty") {
            Byte dst[1] = {'0'};
            CHECK_THROWS_WITH_AS(Stream().view().extract(dst, sizeof(dst)), "end of stream view", const WouldBlock&);
        }

        SUBCASE("trimmed too much") {
            s.trim(s.begin() + 5);
            Byte dst[1] = {'0'};
            CHECK_THROWS_WITH_AS(v.extract(dst, sizeof(dst)), "view starts before available range",
                                 const InvalidIterator&);
        }

        SUBCASE("beginning invalid") {
            s = Stream(); // let view expire
            Byte dst[1] = {'0'};
            CHECK_THROWS_WITH_AS(v.extract(dst, sizeof(dst)), "view has invalid beginning", const InvalidIterator&);
        }

        SUBCASE("gaps") {
            auto s = Stream();
            SUBCASE("just gap") {
                s.append(nullptr, 3); // Gap.
                Byte dst[3] = {};
                REQUIRE_EQ(sizeof(dst), s.size());
                CHECK_THROWS_WITH_AS(s.view().extract(dst, sizeof(dst)), "data is missing", const MissingData&);

                CHECK_EQ(s.statistics().num_data_bytes, 0);
                CHECK_EQ(s.statistics().num_data_chunks, 0);
                CHECK_EQ(s.statistics().num_gap_bytes, 3);
                CHECK_EQ(s.statistics().num_gap_chunks, 1);
            }

            SUBCASE("begin in gap") {
                s.append(nullptr, 2); // Gap.
                s.append("A");
                Byte dst[3] = {};
                REQUIRE_EQ(sizeof(dst), s.size());
                CHECK_THROWS_WITH_AS(s.view().extract(dst, sizeof(dst)), "data is missing", const MissingData&);

                CHECK_EQ(s.statistics().num_data_bytes, 1);
                CHECK_EQ(s.statistics().num_data_chunks, 1);
                CHECK_EQ(s.statistics().num_gap_bytes, 2);
                CHECK_EQ(s.statistics().num_gap_chunks, 1);
            }

            SUBCASE("end in gap") {
                s.append("A");
                s.append(nullptr, 2); // Gap.
                Byte dst[3] = {};
                REQUIRE_EQ(sizeof(dst), s.size());
                CHECK_THROWS_WITH_AS(s.view().extract(dst, sizeof(dst)), "data is missing", const MissingData&);

                CHECK_EQ(s.statistics().num_data_bytes, 1);
                CHECK_EQ(s.statistics().num_data_chunks, 1);
                CHECK_EQ(s.statistics().num_gap_bytes, 2);
                CHECK_EQ(s.statistics().num_gap_chunks, 1);
            }
        }

        SUBCASE("from expanding View") {
            auto s = Stream();
            auto v = s.view();

            Byte dst[3] = {};

            CHECK_THROWS_WITH_AS(v.extract(dst, sizeof(dst)), "end of stream view", const WouldBlock&);

            s.append("A");
            CHECK_THROWS_WITH_AS(v.extract(dst, sizeof(dst)), "end of stream view", const WouldBlock&);

            s.append("B");
            CHECK_THROWS_WITH_AS(v.extract(dst, sizeof(dst)), "end of stream view", const WouldBlock&);

            s.append("C");
            CHECK_EQ(v.extract(dst, sizeof(dst)), ""_b);
            CHECK_EQ(vec(dst), std::vector<Byte>{'A', 'B', 'C'});
        }
    }

    SUBCASE("sub") {
        auto input = "1234567890"_b;
        auto stream = Stream(input);
        auto view = stream.view();

        CHECK_EQ(view.sub(view.end()), view);
        CHECK_EQ(view.sub(view.begin() + view.size()), view);
        CHECK_EQ(view.sub(view.begin() + (view.size() - 1)), "123456789"_b);

        view = view.limit(5);

        CHECK_EQ(view.sub(view.end()), view);
        CHECK_EQ(view.sub(view.begin() + view.size()), view);
        CHECK_EQ(view.sub(view.begin() + (view.size() - 1)), "1234"_b);
    }

    SUBCASE("trimmed view can be appended") {
        auto input = "1234567890"_b;
        auto stream = Stream(input);
        auto view = stream.view();
        REQUIRE_EQ(view.size(), input.size());

        // Trimming removes specified amount of data.
        auto trimmed = view.trim(view.begin() + 3);
        CHECK_EQ(trimmed.size(), input.size() - 3);
        CHECK(trimmed.startsWith("4567890"_b));

        // Trimmed view expands when data is added.
        stream.append("123"_b);
        CHECK_EQ(trimmed.size(), input.size() - 3 + 3);
        CHECK(trimmed.startsWith("4567890123"_b));
    }

    SUBCASE("limited view inherits limit") {
        auto input = "1234567890"_b;
        auto stream = Stream(input);

        // Create a limited view.
        auto limited = stream.view().limit(input.size() / 2);
        REQUIRE_LT(limited.size(), input.size());

        // Trying to increase the limit has no effect.
        auto limit1 = limited.limit(input.size());
        CHECK_EQ(limit1.size(), limited.size());

        // We can still limit a limited view further.
        auto limit2 = limited.limit(limited.size() / 2);
        CHECK_LT(limit2.size(), limited.size());
    }

    SUBCASE("trimmed view inherits limit") {
        auto input = "1234567890"_b;
        auto stream = Stream(input);
        auto view = stream.view();
        REQUIRE_EQ(view.size(), input.size());

        auto limit = 5;
        auto limited = view.limit(limit);
        REQUIRE_EQ(limited.size(), limit);

        auto trim = 3;
        auto trimmed = limited.trim(limited.begin() + trim);

        CHECK_EQ(trimmed.size(), limit - trim);
    }

    SUBCASE("trimmed non-expanding view beyond end") {
        auto input = "012"_b;
        auto stream = Stream(input);

        auto view = stream.view(false);
        REQUIRE_EQ(view.size(), input.size());

        const auto i = view.begin() + 5;

        view = view.trim(i);
        CHECK_EQ(view, ""_b);
        CHECK_EQ(stream, "012"_b);

        stream.append("3456789"_b);
        CHECK_EQ(view, ""_b);
    }

    SUBCASE("trimmed expanding view beyond end") {
        auto input = "012"_b;
        auto stream = Stream(input);

        auto view = stream.view(true);
        REQUIRE_EQ(view.size(), input.size());

        const auto i = view.begin() + 5;

        view = view.trim(i);
        CHECK_EQ(view, ""_b);
        CHECK_EQ(stream, "012"_b);

        stream.append("3456789"_b);
        CHECK_EQ(view, "56789"_b);
    }

    SUBCASE("find - SafeIterator") {
        hilti::rt::Stream s = hilti::rt::Stream("012345678901234567890"_b);
        hilti::rt::stream::View v = s.view().sub(s.at(1), s.at(20));

        hilti::rt::Stream s2 = hilti::rt::Stream("01234567890X"_b);
        hilti::rt::stream::View v2a = s2.view().sub(s2.at(1), s2.at(4));
        hilti::rt::stream::View v2b = s2.view().sub(s2.at(11), s2.at(12));
        hilti::rt::stream::View v2c = s2.view().sub(s2.at(8), s2.end());

        SUBCASE("byte") {
            CHECK_EQ(v.find(Byte('9')), s.at(9));
            CHECK_EQ(v.find(Byte('X')), v.end());
        }

        SUBCASE("byte with start") {
            CHECK_EQ(v.find(Byte('9'), s.at(10)), s.at(19));
            CHECK_EQ(v.find(Byte('X'), s.at(10)), v.end());
        }

        SUBCASE("bytes") {
            auto x = v.find("1"_b);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(1));

            x = v.find("X"_b);
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), v.at(20));

            x = v.find("890X"_b);
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), v.at(18));
        }

        SUBCASE("bytes with start") {
            auto x = v.find("1"_b, s.at(5));
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(11));

            x = v.find("X"_b, s.at(5));
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), v.at(20));

            x = v.find("890X"_b, s.at(5));
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), v.at(18));
        }

        SUBCASE("view") {
            auto x = v.find(v2a);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(1));

            x = v.find(v2b);
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), v.at(20));

            x = v.find(v2c);
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), v.at(18));
        }

        SUBCASE("view with start") {
            auto x = v.find(v2a, s.at(5));
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(11));

            x = v.find(v2b, s.at(5));
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), v.at(20));

            x = v.find(v2c, s.at(5));
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), v.at(18));
        }
    }

    SUBCASE("find - UnsafeIterator") {
        hilti::rt::Stream s = hilti::rt::Stream("012345678901234567890"_b);
        hilti::rt::stream::View v = s.view().sub(s.at(1), s.at(20));

        hilti::rt::Stream s2 = hilti::rt::Stream("01234567890X"_b);
        hilti::rt::stream::View v2a = s2.view().sub(s2.at(1), s2.at(4));
        hilti::rt::stream::View v2b = s2.view().sub(s2.at(11), s2.at(12));
        hilti::rt::stream::View v2c = s2.view().sub(s2.at(8), s2.end());

        SUBCASE("byte") {
            CHECK_EQ(v.find(Byte('9'), hilti::rt::stream::detail::UnsafeConstIterator()),
                     hilti::rt::stream::detail::UnsafeConstIterator(s.at(9)));
            CHECK_EQ(v.find(Byte('X'), hilti::rt::stream::detail::UnsafeConstIterator()), v.unsafeEnd());
        }

        SUBCASE("byte with start") {
            CHECK_EQ(v.find(Byte('9'), hilti::rt::stream::detail::UnsafeConstIterator(s.at(10))),
                     hilti::rt::stream::detail::UnsafeConstIterator(s.at(19)));
            CHECK_EQ(v.find(Byte('X'), hilti::rt::stream::detail::UnsafeConstIterator(s.at(10))), v.unsafeEnd());
        }

        SUBCASE("bytes") {
            auto x = v.find("1"_b, hilti::rt::stream::detail::UnsafeConstIterator());
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), hilti::rt::stream::detail::UnsafeConstIterator(v.at(1)));

            x = v.find("X"_b, hilti::rt::stream::detail::UnsafeConstIterator());
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), hilti::rt::stream::detail::UnsafeConstIterator(v.at(20)));

            x = v.find("890X"_b, hilti::rt::stream::detail::UnsafeConstIterator());
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), hilti::rt::stream::detail::UnsafeConstIterator(v.at(18)));
        }

        SUBCASE("bytes with start") {
            auto x = v.find("1"_b, hilti::rt::stream::detail::UnsafeConstIterator(s.at(5)));
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), hilti::rt::stream::detail::UnsafeConstIterator(v.at(11)));

            x = v.find("X"_b, hilti::rt::stream::detail::UnsafeConstIterator(s.at(5)));
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), hilti::rt::stream::detail::UnsafeConstIterator(v.at(20)));

            x = v.find("890X"_b, hilti::rt::stream::detail::UnsafeConstIterator(s.at(5)));
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), hilti::rt::stream::detail::UnsafeConstIterator(v.at(18)));
        }

        SUBCASE("view") {
            auto x = v.find(v2a, hilti::rt::stream::detail::UnsafeConstIterator());
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), hilti::rt::stream::detail::UnsafeConstIterator(v.at(1)));

            x = v.find(v2b, hilti::rt::stream::detail::UnsafeConstIterator());
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), hilti::rt::stream::detail::UnsafeConstIterator(v.at(20)));

            x = v.find(v2c, hilti::rt::stream::detail::UnsafeConstIterator());
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), hilti::rt::stream::detail::UnsafeConstIterator(v.at(18)));
        }

        SUBCASE("view with start") {
            auto x = v.find(v2a, hilti::rt::stream::detail::UnsafeConstIterator(s.at(5)));
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), hilti::rt::stream::detail::UnsafeConstIterator(v.at(11)));

            x = v.find(v2b, hilti::rt::stream::detail::UnsafeConstIterator(s.at(5)));
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), hilti::rt::stream::detail::UnsafeConstIterator(v.at(20)));

            x = v.find(v2c, hilti::rt::stream::detail::UnsafeConstIterator(s.at(5)));
            CHECK_EQ(tuple::get<0>(x), false);
            CHECK_EQ(tuple::get<1>(x), hilti::rt::stream::detail::UnsafeConstIterator(v.at(18)));
        }
    }

    SUBCASE("find - backwards") {
        SUBCASE("bytes - static view") {
            // This test is value-parameterized over `s`.
            Stream s;
            SUBCASE("single chunk") { s = make_stream({"01234567ABCAB34567890"_b}); }
            SUBCASE("multiple chunks") {
                s = make_stream({
                    "01"_b,
                    "23"_b,
                    "45"_b,
                    "67"_b,
                    "AB"_b,
                    "CA"_b,
                    "B3"_b,
                    "45"_b,
                    "67"_b,
                    "89"_b,
                    "0"_b,
                });
            }

            hilti::rt::stream::View v = s.view().sub(s.at(1), s.at(s.size() - 1));

            auto x = v.find("5"_b, v.at(15), hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(15));

            x = v.find("6"_b, v.at(15), hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(6));

            x = v.find("X"_b, v.at(15), hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), false);

            x = v.find("567"_b, v.at(15), hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(5));

            x = v.find("12"_b, v.at(8), hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(1));

            x = v.find("345"_b, v.at(15), hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(13));

            x = v.find("ABC"_b, v.at(15), hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(8));

            x = v.find("XYZ"_b, v.at(15), hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), false);

            x = v.find("012"_b, v.at(8), hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), false);

            x = v.find(""_b, v.at(1), hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(1));

            x = v.find("1234"_b, v.at(5), hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(1));

            x = v.find("12345"_b, v.at(5), hilti::rt::stream::Direction::Backward); // too long
            CHECK_EQ(tuple::get<0>(x), false);

            x = v.find("789"_b, hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(17));

            CHECK_THROWS_AS(v.find("789"_b, v.end() + 1, hilti::rt::stream::Direction::Backward), InvalidIterator);
            CHECK_THROWS_AS(v.find("789"_b, v.end() + 100, hilti::rt::stream::Direction::Backward), InvalidIterator);
        }

        SUBCASE("bytes - expanding view") {
            // This test is value-parameterized over `s`.
            Stream s;

            SUBCASE("single chunk") { s = make_stream({"012345678901234567890"_b}); }
            SUBCASE("multiple chunks") {
                s = make_stream({
                    "01"_b,
                    "23"_b,
                    "45"_b,
                    "67"_b,
                    "89"_b,
                    "01"_b,
                    "23"_b,
                    "45"_b,
                    "67"_b,
                    "89"_b,
                    "0"_b,
                });
            }

            hilti::rt::stream::View v = s.view(true);

            auto x = v.find("6"_b, v.at(15), hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(6));

            auto i = v.end() + 5;
            CHECK_THROWS_AS(v.find("12345"_b, i, hilti::rt::stream::Direction::Backward), InvalidIterator);

            s.append("12345"_b);
            x = v.find("12345"_b, i, hilti::rt::stream::Direction::Backward);
            CHECK_EQ(tuple::get<0>(x), true);
            CHECK_EQ(tuple::get<1>(x), v.at(21));
        }
    }
}

TEST_SUITE_END();
