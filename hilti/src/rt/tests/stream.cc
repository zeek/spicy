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

TEST_CASE("Constructors") {
    auto b = "xyz"_b;
    CHECK(b.size());
    auto x = Stream("xyz"_b);
    CHECK(to_string(x) == R"(b"xyz")");
    CHECK(! x.isEmpty());
    CHECK(x.size().Ref() == 3);
    CHECK(x.numberChunks() == 1);

    auto y = Stream("123456789012345678901234567890123"_b); // Exceeds small buffer size.
    CHECK(! y.isEmpty());
    CHECK(y.size().Ref() == 33);
    CHECK(y.numberChunks() == 1);
    CHECK(to_string(y) == R"(b"123456789012345678901234567890123")");

    auto z = x;
    x = Stream(""_b);
    CHECK(to_string(z) == R"(b"xyz")");
    CHECK(to_string(x) == R"(b"")");
    CHECK(! z.isEmpty());
    CHECK(z.size().Ref() == 3);

    z = y;
    y = Stream(""_b);
    CHECK(to_string(z) == R"(b"123456789012345678901234567890123")");
    CHECK(to_string(y) == R"(b"")");
    CHECK(! z.isEmpty());
    CHECK(z.size().Ref() == 33);

    x = Stream("xyz"_b);
    z = std::move(x);
    CHECK(to_string(z) == R"(b"xyz")");
    CHECK(! z.isEmpty());
    CHECK(z.size().Ref() == 3);

    y = Stream("123456789012345678901234567890123"_b); // Exceeds small buffer size.
    z = std::move(y);
    CHECK(to_string(z) == R"(b"123456789012345678901234567890123")");
    CHECK(! z.isEmpty());
    CHECK(z.size().Ref() == 33);

    Stream m;
    CHECK(to_string(m) == R"(b"")");
    CHECK(m.isEmpty());
    CHECK(m.size().Ref() == 0);

    m = Stream(""_b);
    CHECK(to_string(m) == R"(b"")");
    CHECK(m.isEmpty());
    CHECK(m.size().Ref() == 0);

    x = Stream("foo"_b);
    CHECK(! x.isFrozen());
    x.freeze();
    CHECK(x.isFrozen());

    CHECK(Stream("abc"_b) == Stream("abc"_b));
    CHECK(Stream("abc"_b) != Stream("def"_b));
    CHECK(Stream("abc"_b) != Stream(""_b));
}

TEST_CASE("Growing") {
    // rvalue append
    auto x = Stream("1234567890"_b);
    CHECK(x.size().Ref() == 10);
    CHECK(x.numberChunks() == 1);

    x.append(""_b);
    CHECK(to_string(x) == R"(b"1234567890")");
    CHECK(x.size().Ref() == 10);
    CHECK(x.numberChunks() == 1);

    x.append("1*3*5*7*9*"_b);
    CHECK(to_string(x) == R"(b"12345678901*3*5*7*9*")");
    CHECK(x.size().Ref() == 20);
    CHECK(x.numberChunks() == 2);

    x.append("123456789012345"_b);
    CHECK(to_string(x) == R"(b"12345678901*3*5*7*9*123456789012345")");
    CHECK(x.size().Ref() == 35);
    CHECK(x.numberChunks() == 3);

    // lvalue append
    x = Stream("1234567890"_b);
    CHECK(x.size().Ref() == 10);
    CHECK(x.numberChunks() == 1);

    auto y1 = ""_b;
    auto y2 = "1*3*5*7*9*"_b;
    auto y3 = "123456789012345"_b;

    x.append(y1);
    CHECK(to_string(x) == R"(b"1234567890")");
    CHECK(x.size().Ref() == 10);
    CHECK(x.numberChunks() == 1);

    x.append(y2);
    CHECK(to_string(x) == R"(b"12345678901*3*5*7*9*")");
    CHECK(x.size().Ref() == 20);
    CHECK(x.numberChunks() == 2);

    x.append(y3);
    CHECK(to_string(x) == R"(b"12345678901*3*5*7*9*123456789012345")");
    CHECK(x.size().Ref() == 35);
    CHECK(x.numberChunks() == 3);
}

TEST_CASE("Iterators") {
    auto x = Stream("12345"_b);

    std::string s;
    for ( auto i : x )
        s += i;

    CHECK(s == "12345");

    x = Stream("12345"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);

    s = "";
    for ( auto i : x )
        s += i;

    CHECK(s == "123451234567890123456789012345678901234567890");

    auto i = x.safeBegin();
    i += 7;
    CHECK(*i == '3');
    i += 7;
    CHECK(*i == '0');
    i += 1;
    CHECK(*i == '1');

    auto j = x.safeEnd();
    CHECK(j != i);
    CHECK(j == x.safeEnd());

    x.append("abc"_b);
    CHECK(j != x.safeEnd());
    CHECK(*j == 'a');

    ++j;
    CHECK(j != x.safeEnd());
    ++j;
    CHECK(j != x.safeEnd());
    ++j;
    CHECK(j == x.safeEnd());

    j += 5;
    CHECK_THROWS_AS(*j, InvalidIterator);
    x.append("1234567890"_b);
    CHECK(*j == '6');

    x = Stream(""_b);
    i = x.safeBegin();
    CHECK_THROWS_AS(*i, InvalidIterator);
    x.append("1"_b);
    CHECK(*i == '1');

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

    CHECK(x.view().sub(i, j) == "6789012345"_b);

    auto y = Stream("12345"_b);
    CHECK(y.view().sub(y.safeBegin(), y.safeEnd()) == "12345"_b);
    CHECK(y.view().sub(y.safeBegin(), y.safeBegin()) == ""_b);
    CHECK(y.view().sub(y.safeEnd(), y.safeEnd()) == ""_b);

    auto f = [](const stream::View& v) { return v.sub(v.safeBegin() + 15, v.safeBegin() + 25); };

    CHECK(Bytes(f(x.view()).data()) == "6789012345"_b);
}

TEST_CASE("freezing") {
    auto x = Stream("12345"_b);
    x.append("123456789A"_b);
    x.append("B234567890"_b);
    x.append("1234567890"_b);
    x.append("123456789D"_b);
    x.append("E234567890"_b);

    auto i = (x.safeBegin() + 25);
    CHECK(! i.isFrozen());
    x.freeze();
    CHECK(i.isFrozen());
    x.unfreeze();
    CHECK(! i.isFrozen());
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
    CHECK(v == "2345ABCDEFG"_b);
    y = Stream(v);
    CHECK(y == "2345ABCDEFG"_b);
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

    CHECK(v1.size().Ref() == 55);
    CHECK(v2.size().Ref() == 5);
}

TEST_CASE("Trim") {
    auto x = Stream("12345678901234567890123456789012"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);
    x.append("1234567890"_b);

    auto y = x;

    CHECK(x.size().Ref() == 72);
    CHECK(x.numberChunks() == 5);

    x.trim(x.at(10));
    CHECK(x.size().Ref() == 62);
    x.trim(x.at(20));
    CHECK(x.safeBegin().offset().Ref() == 20);
    CHECK(x.size().Ref() == 52);
    x.trim(x.at(32));
    CHECK(x.size().Ref() == 40);
    CHECK(x.numberChunks() == 4);
    x.trim(x.at(50));
    CHECK(x.size().Ref() == 22);
    CHECK(x.numberChunks() == 3);
    x.trim(x.at(65));
    CHECK(x.safeBegin().offset().Ref() == 65);
    CHECK(x.size().Ref() == 7);
    CHECK(x == "4567890"_b);
    CHECK(x.numberChunks() == 1);
    x.trim(x.at(72));
    CHECK(x.size().Ref() == 0);
    CHECK(x == ""_b);
    CHECK(x.numberChunks() == 1); // will stay the same
    CHECK(x.safeBegin().offset().Ref() == 72);

    y.trim(y.at(100));
    CHECK(y.size().Ref() == 0);
    CHECK(y.safeBegin().offset().Ref() == 100);

    auto z = Stream("12345"_b);
    z.trim(z.at(3));
    CHECK(z == "45"_b);
    CHECK(z.size().Ref() == 2);
    z.trim(z.at(5));
    CHECK(z == ""_b);
    CHECK(z.size().Ref() == 0);
}

TEST_CASE("Trim with existing iterator and append") {
    auto x = Stream("01"_b);
    auto i = x.safeBegin();
    auto j = x.safeBegin();

    i += 3;
    x.append("2345"_b);
    j += 2;
    x.trim(j);

    CHECK(*i == '3');
}

TEST_CASE("Block iteration") {
    auto content = [](auto b, auto s) -> bool { return memcmp(b->start, s, strlen(s)) == 0; };

    auto x = Stream("01234"_b);

    auto v = x.view();
    auto block = v.firstBlock();
    CHECK(block);
    CHECK(content(block, "01234"));
    CHECK(block->offset == 0);
    CHECK(block->size == 5);
    CHECK(block->is_first);
    CHECK(block->is_last);
    CHECK(! v.nextBlock(block));

    x.append("567"_b);
    x.append("890"_b);
    x.append("abc"_b);
    x.append("def"_b);

    v = x.view();
    block = v.firstBlock();
    CHECK(block);
    CHECK(content(block, "01234"));
    CHECK(block->offset == 0);
    CHECK(block->size == 5);
    CHECK(block->is_first);
    CHECK(! block->is_last);
    block = v.nextBlock(block);
    CHECK(block);
    CHECK(content(block, "567"));
    CHECK(block->offset == 5);
    CHECK(block->size == 3);
    CHECK(! block->is_first);
    CHECK(! block->is_last);
    block = v.nextBlock(block);
    CHECK(block);
    CHECK(content(block, "890"));
    CHECK(block->offset == 8);
    CHECK(block->size == 3);
    CHECK(! block->is_first);
    CHECK(! block->is_last);
    block = v.nextBlock(block);
    CHECK(block);
    CHECK(content(block, "abc"));
    CHECK(block->offset == 11);
    CHECK(block->size == 3);
    CHECK(! block->is_first);
    CHECK(! block->is_last);
    block = v.nextBlock(block);
    CHECK(block);
    CHECK(content(block, "def"));
    CHECK(block->offset == 14);
    CHECK(block->size == 3);
    CHECK(! block->is_first);
    CHECK(block->is_last);
    CHECK(! v.nextBlock(block));

    v = v.sub(v.at(6), v.at(13));
    block = v.firstBlock();
    CHECK(block);
    CHECK(content(block, "67"));
    CHECK(block->offset == 6);
    CHECK(block->size == 2);
    CHECK(block->is_first);
    CHECK(! block->is_last);
    block = v.nextBlock(block);
    CHECK(block);
    CHECK(content(block, "890"));
    CHECK(block->offset == 8);
    CHECK(block->size == 3);
    CHECK(! block->is_first);
    CHECK(! block->is_last);
    block = v.nextBlock(block);
    CHECK(block);
    CHECK(content(block, "ab"));
    CHECK(block->offset == 11);
    CHECK(block->size == 2);
    CHECK(! block->is_first);
    CHECK(block->is_last);
    CHECK(! v.nextBlock(block));
}
