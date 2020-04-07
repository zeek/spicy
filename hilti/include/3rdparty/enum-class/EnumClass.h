//
//  EnumClass.h
//  ArticleEnumClass
//
//  Created by Gabriel Aubut-Lussier on 17-08-07.
//  Copyright © 2017 Gabriel Aubut-Lussier. All rights reserved.
//

#ifndef EnumClass_h
#define EnumClass_h

#include <cassert>
#include <type_traits>

template<typename T>
struct enable_enum_class_bitmask
{
	static constexpr bool value = false;
};

#define enableEnumClassBitmask(T) template<> \
struct enable_enum_class_bitmask<T> \
{ \
static constexpr bool value = true; \
}

/**
 * Wrapper for an enumerator that provides implicit bool conversion
 */
template <typename T>
struct enumerator
{
	constexpr enumerator(const T& value) : value(value) {}
	constexpr explicit operator bool() const
	{
		using underlying_type = typename std::underlying_type<T>::type;
		return static_cast<underlying_type>(value) != 0;
	}
	constexpr operator T() const
	{
		return value;
	}
	
	T value;
};

/**
 * Wrapper that differentiates combined enumerators from a single enumerator
 * to provent accidental comparisons between a bitmask and a single enumerator
 * using operator== or operator!=
 */
template <typename T>
struct bitmask
{
	using underlying_type = typename std::underlying_type<T>::type;
	
	constexpr bitmask(const T& value) : value(static_cast<underlying_type>(value)) {}
	constexpr bitmask(const enumerator<T>& enumerator) : value(static_cast<underlying_type>(enumerator.value)) {}
	constexpr explicit operator bool() const
	{
		return value != 0;
	}
	
	underlying_type value;
};

template<typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
make_bitmask(const T& t)
{
	return bitmask<T>{t};
}

/**
 * operator&(T, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, enumerator<T>>::type
operator&(const T& lhs, const T& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	assert((static_cast<underlying_type>(lhs) & (static_cast<underlying_type>(lhs) - 1)) == 0);
	return enumerator<T>{static_cast<T>(static_cast<underlying_type>(lhs) & static_cast<underlying_type>(rhs))};
}

/**
 * operator&(enumerator<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, enumerator<T>>::type
operator&(const enumerator<T>& lhs, const enumerator<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return enumerator<T>{static_cast<T>(static_cast<underlying_type>(lhs.value) & static_cast<underlying_type>(rhs.value))};
}

/**
 * operator&(bitmask<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator&(const bitmask<T>& lhs, const bitmask<T>& rhs)
{
	return bitmask<T>{static_cast<T>(lhs.value & rhs.value)};
}

/**
 * operator&(bitmask<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, enumerator<T>>::type
operator&(const bitmask<T>& lhs, const T& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return enumerator<T>{static_cast<T>(lhs.value & static_cast<underlying_type>(rhs))};
}

/**
 * operator&(T, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, enumerator<T>>::type
operator&(const T& lhs, const bitmask<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return enumerator<T>{static_cast<T>(static_cast<underlying_type>(lhs) & rhs.value)};
}

/**
 * operator&(bitmask<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, enumerator<T>>::type
operator&(const bitmask<T>& lhs, const enumerator<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return enumerator<T>{static_cast<T>(lhs.value & static_cast<underlying_type>(rhs.value))};
}

/**
 * operator&(enumerator<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, enumerator<T>>::type
operator&(const enumerator<T>& lhs, const bitmask<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return enumerator<T>{static_cast<T>(static_cast<underlying_type>(lhs.value) & rhs.value)};
}

/**
 * operator&(T, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, enumerator<T>>::type
operator&(const T& lhs, const enumerator<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return enumerator<T>{static_cast<T>(static_cast<underlying_type>(lhs) & static_cast<underlying_type>(rhs.value))};
}

/**
 * operator&(enumerator<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, enumerator<T>>::type
operator&(const enumerator<T>& lhs, const T& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return enumerator<T>{static_cast<T>(static_cast<underlying_type>(lhs.value) & static_cast<underlying_type>(rhs))};
}

/**
 * operator|(T, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator|(const T& lhs, const T& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(static_cast<underlying_type>(lhs) | static_cast<underlying_type>(rhs))};
}

/**
 * operator|(enumerator<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator|(const enumerator<T>& lhs, const enumerator<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(static_cast<underlying_type>(lhs.value) | static_cast<underlying_type>(rhs.value))};
}

/**
 * operator|(bitmask<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator|(const bitmask<T>& lhs, const bitmask<T>& rhs)
{
	return bitmask<T>{static_cast<T>(lhs.value | rhs.value)};
}

/**
 * operator|(bitmask<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator|(const bitmask<T>& lhs, const T& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(lhs.value | static_cast<underlying_type>(rhs))};
}

/**
 * operator|(T, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator|(const T& lhs, const bitmask<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(static_cast<underlying_type>(lhs) | rhs.value)};
}

/**
 * operator|(bitmask<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator|(const bitmask<T>& lhs, const enumerator<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(lhs.value | static_cast<underlying_type>(rhs.value))};
}

/**
 * operator|(enumerator<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator|(const enumerator<T>& lhs, const bitmask<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(static_cast<underlying_type>(lhs.value) | rhs.value)};
}

/**
 * operator|(enumerator<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator|(const enumerator<T>& lhs, const T& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(static_cast<underlying_type>(lhs.value) | static_cast<underlying_type>(rhs))};
}

/**
 * operator|(T, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator|(const T& lhs, const enumerator<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(static_cast<underlying_type>(lhs) | static_cast<underlying_type>(rhs.value))};
}

/**
 * operator^(T, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator^(const T& lhs, const T& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(static_cast<underlying_type>(lhs) ^ static_cast<underlying_type>(rhs))};
}

/**
 * operator^(enumerator<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator^(const enumerator<T>& lhs, const enumerator<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(static_cast<underlying_type>(lhs.value) ^ static_cast<underlying_type>(rhs.value))};
}

/**
 * operator^(bitmask<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator^(const bitmask<T>& lhs, const bitmask<T>& rhs)
{
	return bitmask<T>{static_cast<T>(lhs.value ^ rhs.value)};
}

/**
 * operator^(bitmask<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator^(const bitmask<T>& lhs, const T& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(lhs.value ^ static_cast<underlying_type>(rhs))};
}

/**
 * operator^(T, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator^(const T& lhs, const bitmask<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(static_cast<underlying_type>(lhs) ^ rhs.value)};
}

/**
 * operator^(bitmask<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator^(const bitmask<T>& lhs, const enumerator<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(lhs.value ^ static_cast<underlying_type>(rhs.value))};
}

/**
 * operator^(enumerator<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator^(const enumerator<T>& lhs, const bitmask<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(static_cast<underlying_type>(lhs.value) ^ rhs.value)};
}

/**
 * operator^(enumerator<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator^(const enumerator<T>& lhs, const T& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(static_cast<underlying_type>(lhs.value) ^ static_cast<underlying_type>(rhs))};
}

/**
 * operator^(T, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator^(const T& lhs, const enumerator<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(static_cast<underlying_type>(lhs) ^ static_cast<underlying_type>(rhs.value))};
}

/**
 * operator~(T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator~(const T& value)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(~ static_cast<underlying_type>(value))};
}

/**
 * operator~(enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator~(const enumerator<T>& lhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	return bitmask<T>{static_cast<T>(~ static_cast<underlying_type>(lhs.value))};
}

/**
 * operator~(bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>>::type
operator~(const bitmask<T>& lhs)
{
	return bitmask<T>{static_cast<T>(~ lhs.value)};
}

/**
 * operator&=(bitmask<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>&>::type
operator&=(bitmask<T>& lhs, const T& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	lhs.value &= static_cast<underlying_type>(rhs);
	return lhs;
}

/**
 * operator&=(bitmask<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>&>::type
operator&=(bitmask<T>& lhs, const enumerator<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	lhs.value &= static_cast<underlying_type>(rhs.value);
	return lhs;
}

/**
 * operator&=(bitmask<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>&>::type
operator&=(bitmask<T>& lhs, const bitmask<T>& rhs)
{
	lhs.value &= rhs.value;
	return lhs;
}

/**
 * operator|=(bitmask<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>&>::type
operator|=(bitmask<T>& lhs, const T& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	lhs.value |= static_cast<underlying_type>(rhs);
	return lhs;
}

/**
 * operator|=(bitmask<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>&>::type
operator|=(bitmask<T>& lhs, const enumerator<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	lhs.value |= static_cast<underlying_type>(rhs.value);
	return lhs;
}

/**
 * operator|=(bitmask<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>&>::type
operator|=(bitmask<T>& lhs, const bitmask<T>& rhs)
{
	lhs.value |= rhs.value;
	return lhs;
}

/**
 * operator^=(bitmask<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>&>::type
operator^=(bitmask<T>& lhs, const T& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	lhs.value ^= static_cast<underlying_type>(rhs);
	return lhs;
}

/**
 * operator^=(bitmask<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>&>::type
operator^=(bitmask<T>& lhs, const enumerator<T>& rhs)
{
	using underlying_type = typename std::underlying_type<T>::type;
	lhs.value ^= static_cast<underlying_type>(rhs.value);
	return lhs;
}

/**
 * operator^=(bitmask<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bitmask<T>&>::type
operator^=(bitmask<T>& lhs, const bitmask<T>& rhs)
{
	lhs.value ^= rhs.value;
	return lhs;
}

/**
 * operator==(T, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator==(const T& lhs, const T& rhs)
{
	return lhs == rhs;
}

/**
 * operator==(enumerator<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator==(const enumerator<T>& lhs, const enumerator<T>& rhs)
{
	return lhs.value == rhs.value;
}

/**
 * operator==(bitmask<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator==(const bitmask<T>& lhs, const bitmask<T>& rhs)
{
	return lhs.value == rhs.value;
}

/**
 * operator==(enumerator<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator==(const enumerator<T>& lhs, const T& rhs)
{
	return lhs.value == rhs;
}

/**
 * operator==(T, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator==(const T& lhs, const enumerator<T>& rhs)
{
	return lhs == rhs.value;
}

/**
 * operator==(bitmask<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator==(const bitmask<T>& /* lhs */, const T& /* rhs */)
{
	static_assert(!std::is_same<typename bitmask<T>::underlying_type, typename std::underlying_type<T>::type>::value, "A bitmask can't be compared to an enumerator. Use & first.");
	return false;
}

/**
 * operator==(T, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator==(const T& /* lhs */, const bitmask<T>& /* rhs */)
{
	static_assert(!std::is_same<typename bitmask<T>::underlying_type, typename std::underlying_type<T>::type>::value, "A bitmask can't be compared to an enumerator. Use & first.");
	return false;
}

/**
 * operator==(bitmask<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator==(const bitmask<T>& /* lhs */, const enumerator<T>& /* rhs */)
{
	static_assert(!std::is_same<typename bitmask<T>::underlying_type, typename std::underlying_type<T>::type>::value, "A bitmask can't be compared to an enumerator. Use & first.");
	return false;
}

/**
 * operator==(enumerator<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator==(const enumerator<T>& /* lhs */, const bitmask<T>& /* rhs */)
{
	static_assert(!std::is_same<typename bitmask<T>::underlying_type, typename std::underlying_type<T>::type>::value, "A bitmask can't be compared to an enumerator. Use & first.");
	return false;
}

/**
 * operator!=(T, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator!=(const T& lhs, const T& rhs)
{
	return lhs != rhs;
}

/**
 * operator!=(enumerator<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator!=(const enumerator<T>& lhs, const enumerator<T>& rhs)
{
	return lhs.value != rhs.value;
}

/**
 * operator!=(bitmask<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator!=(const bitmask<T>& lhs, const bitmask<T>& rhs)
{
	return lhs.value != rhs.value;
}

/**
 * operator!=(enumerator<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator!=(const enumerator<T>& lhs, const T& rhs)
{
	return lhs.value != rhs;
}

/**
 * operator!=(T, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator!=(const T& lhs, const enumerator<T>& rhs)
{
	return lhs != rhs.value;
}

/**
 * operator!=(bitmask<T>, T)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator!=(const bitmask<T>& /* lhs */, const T& /* rhs */)
{
	static_assert(!std::is_same<typename bitmask<T>::underlying_type, typename std::underlying_type<T>::type>::value, "A bitmask can't be compared to an enumerator. Use & first.");
	return false;
}

/**
 * operator!=(T, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator!=(const T& /* lhs */, const bitmask<T>& /* rhs */)
{
	static_assert(!std::is_same<typename bitmask<T>::underlying_type, typename std::underlying_type<T>::type>::value, "A bitmask can't be compared to an enumerator. Use & first.");
	return false;
}

/**
 * operator!=(bitmask<T>, enumerator<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator!=(const bitmask<T>& /* lhs */, const enumerator<T>& /* rhs */)
{
	static_assert(!std::is_same<typename bitmask<T>::underlying_type, typename std::underlying_type<T>::type>::value, "A bitmask can't be compared to an enumerator. Use & first.");
	return false;
}

/**
 * operator!=(enumerator<T>, bitmask<T>)
 */
template <typename T>
constexpr
typename std::enable_if<std::is_enum<T>::value && enable_enum_class_bitmask<T>::value, bool>::type
operator!=(const enumerator<T>& /* lhs */, const bitmask<T>& /* rhs */)
{
	static_assert(!std::is_same<typename bitmask<T>::underlying_type, typename std::underlying_type<T>::type>::value, "A bitmask can't be compared to an enumerator. Use & first.");
	return false;
}

#endif /* EnumClass_h */
