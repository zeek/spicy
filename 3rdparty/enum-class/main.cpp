//
//  main.cpp
//  ArticleEnumClass_v2
//
//  Created by Gabriel Aubut-Lussier on 17-08-07.
//  Copyright © 2017 Gabriel Aubut-Lussier. All rights reserved.
//

#include <cassert>
#include "EnumClass.h"
#include <iostream>

enum class eTest
{
	kEnumerator1 = 1 << 0,
	kEnumerator2 = 1 << 1,
	kEnumerator3 = 1 << 2
};
enableEnumClassBitmask(eTest);

constexpr bool f(eTest e) {return e != static_cast<eTest>(0);}
constexpr bool g(enumerator<eTest> e) {return bool(e);}
constexpr bool h(bitmask<eTest> e) {return bool(e);}

int main(int argc, const char * argv[])
{
	constexpr auto t = eTest::kEnumerator1;
	constexpr auto enumerator = ::enumerator<eTest>{t};
	constexpr auto bitmask = t | eTest::kEnumerator2;
	
	/**
	 * operator&
	 */
	static_assert(t & t, "operator&(T, T)");
	static_assert(enumerator & enumerator, "operator&(enumerator<T>, enumerator<T>)");
	static_assert(bitmask & bitmask, "operator&(bitmask<T>, bitmask<T>)");
	static_assert(t & enumerator, "operator&(T, enumerator<T>)");
	static_assert(enumerator & t, "operator&(enumerator<T>, T)");
	static_assert(t & bitmask, "operator&(T, bitmask<T>)");
	static_assert(bitmask & t, "operator&(bitmask<T>, T)");
	static_assert(enumerator & bitmask, "operator&(enumerator<T>, bitmask<T>)");
	static_assert(bitmask & enumerator, "operator&(bitmask<T>, enumerator<T>)");
	
	/**
	 * operator|
	 */
	static_assert(enumerator | enumerator, "operator|(T, T)");
	static_assert(enumerator | enumerator, "operator|(enumerator<T>, enumerator<T>)");
	static_assert(bitmask | bitmask, "operator|(bitmask<T>, bitmask<T>)");
	static_assert(t | enumerator, "operator|(T, enumerator<T>)");
	static_assert(enumerator | t, "operator|(enumerator<T>, T)");
	static_assert(t | bitmask, "operator|(T, bitmask<T>)");
	static_assert(bitmask | t, "operator|(bitmask<T>, T)");
	static_assert(enumerator | bitmask, "operator|(enumerator<T>, bitmask<T>)");
	static_assert(bitmask | enumerator, "operator|(bitmask<T>, enumerator<T>)");
	
	/**
	 * operator^
	 */
	static_assert(!bool(t ^ t), "operator^(T, T)");
	static_assert(!bool(enumerator ^ enumerator), "operator^(enumerator<T>, enumerator<T>)");
	static_assert(!bool(bitmask ^ bitmask), "operator^(bitmask<T>, bitmask<T>)");
	static_assert(!bool(t ^ enumerator), "operator^(T, enumerator<T>)");
	static_assert(!bool(enumerator ^ t), "operator^(enumerator<T>, T)");
	static_assert(t ^ bitmask, "operator^(T, bitmask<T>)");
	static_assert(bitmask ^ t, "operator^(bitmask<T>, T)");
	static_assert(enumerator ^ bitmask, "operator^(enumerator<T>, bitmask<T>)");
	static_assert(bitmask ^ enumerator, "operator^(bitmask<T>, enumerator<T>)");
	
	/**
	 * operator~
	 */
	static_assert(~t, "operator~(T)");
	static_assert(~enumerator, "operator~(enumerator<T>)");
	static_assert(~bitmask, "operator~(bitmask<T>)");
	
	/**
	 * operator&=
	 */
	auto mutbitmask = bitmask;
	mutbitmask &= t;
	mutbitmask &= enumerator;
	mutbitmask &= mutbitmask;
	assert(bitmask);
	
	/**
	 * operator|=
	 */
	mutbitmask |= t;
	mutbitmask |= enumerator;
	mutbitmask |= mutbitmask;
	assert(mutbitmask);
	
	/**
	 * operator^=
	 */
	mutbitmask ^= t;
	mutbitmask ^= enumerator;
	mutbitmask ^= mutbitmask;
	assert(!mutbitmask);
	
	/**
	 * bitmask::operator bool
	 */
	assert(!bool(mutbitmask));
	
	/**
	 * operator==
	 */
	static_assert(t == t, "operator==(T, T)");
	static_assert(enumerator == enumerator, "operator==(enumerator<T>, enumerator<T>)");
	static_assert(bitmask == bitmask, "operator==(bitmask<T>, bitmask<T>)");
	static_assert(t == enumerator, "operator==(T, enumerator<T>)");
	static_assert(enumerator == t, "operator==(enumerator<T>, T)");
//	static_assert(t == bitmask, "operator==(T, bitmask<T>)");
//	static_assert(bitmask == t, "operator==(bitmask<T>, T)");
//	static_assert(enumerator == bitmask, "operator==(enumerator<T>, bitmask<T>)");
//	static_assert(bitmask == enumerator, "operator==(bitmask<T>, enumerator<T>)");
	
	/**
	 * operator!=
	 */
	static_assert(!(t != t), "operator!=(T, T)");
	static_assert(!(enumerator != enumerator), "operator!=(enumerator<T>, enumerator<T>)");
	static_assert(!(bitmask != bitmask), "operator!=(bitmask<T>, bitmask<T>)");
	static_assert(!(t != enumerator), "operator!=(T, enumerator<T>)");
	static_assert(!(enumerator != t), "operator!=(enumerator<T>, T)");
//	static_assert(t != bitmask, "operator!=(T, bitmask<T>)");
//	static_assert(bitmask != t, "operator!=(bitmask<T>, T)");
//	static_assert(enumerator != bitmask, "operator!=(enumerator<T>, bitmask<T>)");
//	static_assert(bitmask != enumerator, "operator!=(bitmask<T>, enumerator<T>)");
	
	static_assert(enumerator, "enumerator<T>::operator bool()");
	static_assert(bitmask, "bitmask<T>::operator bool()");
	
	static_assert(f(t), "no conversion");
	static_assert(f(enumerator), "enumerator<T>::operator T() implicit conversion");
	static_assert(g(t), "enumerator<T>(T) implicit conversion");
	static_assert(h(t), "bitmask<T>(T) implicit conversion");
	static_assert(h(enumerator), "bitmask<T>(enumerator<T>) implicit conversion");
	
	static_assert(g(bitmask & t), "It must be possible to isolate a single enumerator from a bitmask");
	
	static_assert(make_bitmask(t) == ::bitmask<eTest>{t}, "Must be able to easily make a bitmask from a single enumerator");
}
