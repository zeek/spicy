// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <exception>
#include <sstream>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes;
using namespace hilti::rt::stream;
using hilti::rt::to_string;

TEST_SUITE_BEGIN("Stream");

auto make_stream(std::initializer_list<Bytes> xs) {
    Stream s;
    for ( auto&& x : xs )
        s.append(x);

    return s;
}

TEST_CASE("Constructors") {
    auto b = "xyz"_b;
    CHECK_GT(b.size(), 0);
    CHECK_FALSE(b.isEmpty());
    auto x = Stream("xyz"_b);
    CHECK_EQ(to_string(x), R"(b"xyz")");
    CHECK_FALSE(x.isEmpty());
    CHECK_EQ(x.size().Ref(), 3);
    CHECK_EQ(x.numberChunks(), 1);

    auto y = Stream("123456789012345678901234567890123"_b); // Exceeds small buffer size.
    CHECK_FALSE(y.isEmpty());
    CHECK_EQ(y.size().Ref(), 33);
    CHECK_EQ(y.numberChunks(), 1);
    CHECK_EQ(to_string(y), R"(b"123456789012345678901234567890123")");

    auto z = x;
    x = Stream(""_b);
    CHECK_EQ(to_string(z), R"(b"xyz")");
    CHECK_EQ(to_string(x), R"(b"")");
    CHECK_FALSE(z.isEmpty());
    CHECK_EQ(z.size().Ref(), 3);

    z = y;
    y = Stream(""_b);
    CHECK_EQ(to_string(z), R"(b"123456789012345678901234567890123")");
    CHECK_EQ(to_string(y), R"(b"")");
    CHECK_FALSE(z.isEmpty());
    CHECK_EQ(z.size().Ref(), 33);

    x = Stream("xyz"_b);
    z = std::move(x);
    CHECK_EQ(to_string(z), R"(b"xyz")");
    CHECK_FALSE(z.isEmpty());
    CHECK_EQ(z.size().Ref(), 3);

    y = Stream("123456789012345678901234567890123"_b); // Exceeds small buffer size.
    z = std::move(y);
    CHECK_EQ(to_string(z), R"(b"123456789012345678901234567890123")");
    CHECK_FALSE(z.isEmpty());
    CHECK_EQ(z.size().Ref(), 33);

    Stream m;
    CHECK_EQ(to_string(m), R"(b"")");
    CHECK(m.isEmpty());
    CHECK_EQ(m.size().Ref(), 0);

    m = Stream(""_b);
    CHECK_EQ(to_string(m), R"(b"")");
    CHECK(m.isEmpty());
    CHECK_EQ(m.size().Ref(), 0);

    x = Stream("foo"_b);
    CHECK_FALSE(x.isFrozen());
    x.freeze();
    CHECK(x.isFrozen());

    CHECK_EQ(Stream("abc"_b), Stream("abc"_b));
    CHECK_NE(Stream("abc"_b), Stream("def"_b));
    CHECK_NE(Stream("abc"_b), Stream(""_b));

    CHECK_EQ(Stream(std::vector<Byte>({'1', '2', '3'})), Stream("123"_b));

    {
        auto xs = "123"_b;
        const auto s = Stream(xs.data(), xs.size());
        CHECK_EQ(s, Stream("123"_b));
        // Underlying data is copied.
        xs = "456"_b;
        CHECK_EQ(s, Stream("123"_b));
    }

    {
        auto s = Stream("123"_b);
        CHECK_EQ(Stream(std::move(s)), Stream("123"_b));
    }

    {
        const auto SmallBufferSize = stream::detail::Chunk::SmallBufferSize;

        auto d1 = std::string(1, '\x01');
        REQUIRE_LT(d1.size(), SmallBufferSize);
        CHECK_EQ(Stream(d1.c_str()).data(), d1);

        auto d2 = std::string(SmallBufferSize + 10, '\x01');
        CHECK_EQ(Stream(d2.c_str()).data(), d2);
    }

    { // Self-assignment is a no-op.
        auto s = Stream("123"_b);

        *&s = s; // Assign through a pointer to not trigger compiler warnings about self-assignments.
        CHECK_EQ(s, Stream("123"_b));

        *&s = std::move(s); // Assign through a pointer to not trigger compiler warnings about self-assignments.
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

TEST_CASE("Growing") {
    // rvalue append
    auto x = Stream("1234567890"_b);
    CHECK_EQ(x.size().Ref(), 10);
    CHECK_EQ(x.numberChunks(), 1);

    x.append(""_b);
    CHECK_EQ(to_string(x), R"(b"1234567890")");
    CHECK_EQ(x.size().Ref(), 10);
    CHECK_EQ(x.numberChunks(), 1);

    x.append("1*3*5*7*9*"_b);
    CHECK_EQ(to_string(x), R"(b"12345678901*3*5*7*9*")");
    CHECK_EQ(x.size().Ref(), 20);
    CHECK_EQ(x.numberChunks(), 2);

    x.append("123456789012345"_b);
    CHECK_EQ(to_string(x), R"(b"12345678901*3*5*7*9*123456789012345")");
    CHECK_EQ(x.size().Ref(), 35);
    CHECK_EQ(x.numberChunks(), 3);

    // lvalue append
    x = Stream("1234567890"_b);
    CHECK_EQ(x.size().Ref(), 10);
    CHECK_EQ(x.numberChunks(), 1);

    auto y1 = ""_b;
    auto y2 = "1*3*5*7*9*"_b;
    auto y3 = "123456789012345"_b;

    x.append(y1);
    CHECK_EQ(to_string(x), R"(b"1234567890")");
    CHECK_EQ(x.size().Ref(), 10);
    CHECK_EQ(x.numberChunks(), 1);

    x.append(y2);
    CHECK_EQ(to_string(x), R"(b"12345678901*3*5*7*9*")");
    CHECK_EQ(x.size().Ref(), 20);
    CHECK_EQ(x.numberChunks(), 2);

    x.append(y3);
    CHECK_EQ(to_string(x), R"(b"12345678901*3*5*7*9*123456789012345")");
    CHECK_EQ(x.size().Ref(), 35);
    CHECK_EQ(x.numberChunks(), 3);
}

TEST_CASE("Iterators") {
    auto x = Stream("12345"_b);

    std::string s;
    for ( auto i : x )
        s += i;

    CHECK_EQ(s, "12345");

    x = Stream("12345"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);

    s = "";
    for ( auto i : x )
        s += i;

    CHECK_EQ(s, "123451234567890123456789012345678901234567890");

    auto i = x.safeBegin();
    i += 7;
    CHECK_EQ(*i, '3');
    i += 7;
    CHECK_EQ(*i, '0');
    i += 1;
    CHECK_EQ(*i, '1');

    auto j = x.safeEnd();
    CHECK_NE(j, i);
    CHECK_EQ(j, x.safeEnd());

    x.append("abc"_b);
    CHECK_NE(j, x.safeEnd());
    CHECK_EQ(*j, 'a');

    ++j;
    CHECK_NE(j, x.safeEnd());
    ++j;
    CHECK_NE(j, x.safeEnd());
    ++j;
    CHECK_EQ(j, x.safeEnd());

    j += 5;
    CHECK_THROWS_AS(*j, InvalidIterator);
    x.append("1234567890"_b);
    CHECK_EQ(*j, '6');

    x = Stream(""_b);
    i = x.safeBegin();
    CHECK_THROWS_AS(*i, InvalidIterator);
    x.append("1"_b);
    CHECK_EQ(*i, '1');

    CHECK_THROWS_AS((void)(*j == '6'), InvalidIterator); // j now invalid.
}

TEST_CASE("sub") {
    auto x = Stream("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);

    auto i = (x.safeBegin() + 5);
    auto j = (x.safeBegin() + 15);

    CHECK_EQ(x.view().sub(i, j), "6789012345"_b);

    auto y = Stream("12345"_b);
    CHECK_EQ(y.view().sub(y.safeBegin(), y.safeEnd()), "12345"_b);
    CHECK_EQ(y.view().sub(y.safeBegin(), y.safeBegin()), ""_b);
    CHECK_EQ(y.view().sub(y.safeEnd(), y.safeEnd()), ""_b);

    auto f = [](const stream::View& v) { return v.sub(v.safeBegin() + 15, v.safeBegin() + 25); };

    CHECK_EQ(Bytes(f(x.view()).data()), "6789012345"_b);
}

TEST_CASE("freezing") {
    auto x = Stream("12345"_b);
    x.append("123456789A"_b);
    x.append("B234567890"_b);
    x.append("1234567890"_b);
    x.append("123456789D"_b);
    x.append("E234567890"_b);

    auto i = (x.safeBegin() + 25);
    CHECK_FALSE(i.isFrozen());
    x.freeze();
    CHECK(i.isFrozen());
    x.unfreeze();
    CHECK_FALSE(i.isFrozen());
}

TEST_CASE("convert view to stream") {
    auto x = Stream("12345"_b);
    auto v = stream::View(x.safeBegin() + 1, x.safeBegin() + 3);
    CHECK(v == "23"_b);
    auto y = Stream(v);
    CHECK(y == "23"_b);

    x.append("ABCDEF"_b);
    x.append("GHJI"_b);
    v = stream::View(x.safeBegin() + 1, x.safeBegin() + 12);
    CHECK_EQ(v, "2345ABCDEFG"_b);
    y = Stream(v);
    CHECK_EQ(y, "2345ABCDEFG"_b);
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
    CHECK_EQ(x.numberChunks(), 5);

    x.trim(x.at(10));
    CHECK_EQ(x.size().Ref(), 62);
    x.trim(x.at(20));
    CHECK_EQ(x.safeBegin().offset().Ref(), 20);
    CHECK_EQ(x.size().Ref(), 52);
    x.trim(x.at(32));
    CHECK_EQ(x.size().Ref(), 40);
    CHECK_EQ(x.numberChunks(), 4);
    x.trim(x.at(50));
    CHECK_EQ(x.size().Ref(), 22);
    CHECK_EQ(x.numberChunks(), 3);
    x.trim(x.at(65));
    CHECK_EQ(x.safeBegin().offset().Ref(), 65);
    CHECK_EQ(x.size().Ref(), 7);
    CHECK_EQ(x, "4567890"_b);
    CHECK_EQ(x.numberChunks(), 1);
    x.trim(x.at(72));
    CHECK_EQ(x.size().Ref(), 0);
    CHECK_EQ(x, ""_b);
    CHECK_EQ(x.numberChunks(), 1); // will stay the same
    CHECK_EQ(x.safeBegin().offset().Ref(), 72);

    y.trim(y.at(100));
    CHECK_EQ(y.size().Ref(), 0);
    CHECK_EQ(y.safeBegin().offset().Ref(), 100);

    auto z = Stream("12345"_b);
    z.trim(z.at(3));
    CHECK_EQ(z, "45"_b);
    CHECK_EQ(z.size().Ref(), 2);
    z.trim(z.at(5));
    CHECK_EQ(z, ""_b);
    CHECK_EQ(z.size().Ref(), 0);
}

TEST_CASE("Trim with existing iterator and append") {
    auto x = Stream("01"_b);
    auto i = x.safeBegin();
    auto j = x.safeBegin();

    i += 3;
    x.append("2345"_b);
    j += 2;
    x.trim(j);

    CHECK_EQ(*i, '3');
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
    CHECK_EQ(to_string(stream.safeBegin()), fmt("<offset=0 data=%s>", to_string(bytes)));
}

TEST_SUITE_END();

TEST_SUITE_BEGIN("View");

TEST_CASE("advance") {
    auto input = "1234567890"_b;
    auto stream = Stream(input);
    auto view = stream.view();

    REQUIRE_EQ(view.size(), input.size());

    auto advance = 5;
    view = view.advance(advance);

    CHECK_EQ(view.size(), input.size() - advance);
    CHECK(view.startsWith("67890"_b));
}

TEST_CASE("equal") {
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

template<typename T, int N>
std::vector<T> vec(T (&xs)[N]) {
    std::vector<T> ys;
    ys.assign(xs, xs + N);
    return ys;
}

TEST_CASE("extract") {
    const auto s = Stream("1234567890"_b);
    const auto v = s.view();

    SUBCASE("1") {
        Byte dst[1] = {'0'};
        CHECK_EQ(v.extract(dst), "234567890"_b);
        CHECK_EQ(vec(dst), std::vector<Byte>({'1'}));
    }

    SUBCASE("3") {
        Byte dst[3] = {'0'};
        CHECK_EQ(v.extract(dst), "4567890"_b);
        CHECK_EQ(vec(dst), std::vector<Byte>({'1', '2', '3'}));
    }

    SUBCASE("all") {
        Byte dst[10] = {'0'};
        CHECK_EQ(v.extract(dst), ""_b);
        CHECK_EQ(vec(dst), std::vector<Byte>({'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}));
    }

    SUBCASE("empty") {
        Byte dst[1] = {'0'};
        CHECK_THROWS_WITH_AS(Stream().view().extract(dst), "end of stream view", const WouldBlock&);
    }
}

TEST_CASE("sub") {
    auto input = "1234567890"_b;
    auto stream = Stream(input);
    auto view = stream.view();

    CHECK_EQ(view.sub(view.safeEnd()), view);
    CHECK_EQ(view.sub(view.safeBegin() + view.size()), view);
    CHECK_EQ(view.sub(view.safeBegin() + (view.size() - 1)), "123456789"_b);

    view = view.limit(5);

    CHECK_EQ(view.sub(view.safeEnd()), view);
    CHECK_EQ(view.sub(view.safeBegin() + view.size()), view);
    CHECK_EQ(view.sub(view.safeBegin() + (view.size() - 1)), "1234"_b);
}

TEST_CASE("trimmed view can be appended") {
    auto input = "1234567890"_b;
    auto stream = Stream(input);
    auto view = stream.view();
    REQUIRE_EQ(view.size(), input.size());

    // Trimming removes specified amount of data.
    auto trimmed = view.trim(view.safeBegin() + 3);
    CHECK_EQ(trimmed.size(), input.size() - 3);
    CHECK(trimmed.startsWith("4567890"_b));

    // Trimmed view expands when data is added.
    stream.append("123"_b);
    CHECK_EQ(trimmed.size(), input.size() - 3 + 3);
    CHECK(trimmed.startsWith("4567890123"));
}

TEST_CASE("trimmed view inherits limit") {
    auto input = "1234567890"_b;
    auto stream = Stream(input);
    auto view = stream.view();
    REQUIRE_EQ(view.size(), input.size());

    auto limit = 5;
    auto limited = view.limit(limit);
    REQUIRE_EQ(limited.size(), limit);

    auto trim = 3;
    auto trimmed = limited.trim(limited.safeBegin() + trim);

    CHECK_EQ(trimmed.size(), limit - trim);
}

TEST_SUITE_END();
