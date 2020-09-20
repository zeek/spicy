# Bitmask operators and typesafe comparisons for enum class
*EnumClass.h* is a utility header that allows you to easily generate bitwise operators for your custom `enum class` type like so:
```cpp
enum class myEnum
{
	enumerator1 = 0x1 << 0,
	enumerator2 = 0x1 << 1,
	enumerator3 = 0x1 << 2
};

enableEnumClassBitmask(myEnum); // Activate bitmask operators
```
This utility relies on two concepts: enumerators and masks. An enumerator’s purpose is to give a name to a specific bit when it is set. A mask, on the other hand, represents the state of every bit (and this way, of every enumerator), whether they are set or cleared. Comparing an enumerator to a mask using `operator==` or `operator!=` is a compiler error. [A complete blog post](https://dalzhim.github.io/2017/08/11/Improving-the-enum-class-bitmask/) explains why and how this is implemented.

Here are some tables that summarize the return type of all of the operators :

#### Binary bitwise operators

 | **`E, E`** | **`E`, `bitmask<E>`** | **`bitmask<E>`, `E`** | **`bitmask<E>`, `bitmask<E>`**
 | ---------- | --------------------- | --------------------- | ------------------------------
**`operator&`** | `E` | `E` | `E` | `bitmask<E>`
**`operator\|`** | `bitmask<E>` | `bitmask<E>` | `bitmask<E>` | `bitmask<E>`
**`operator^`** | `bitmask<E>` | `bitmask<E>` | `bitmask<E>` | `bitmask<E>`
**`operator&=`** | `bitmask<E>` | `bitmask<E>` | `bitmask<E>` | `bitmask<E>`
**`operator\|=`** | `bitmask<E>` | `bitmask<E>` | `bitmask<E>` | `bitmask<E>`
**`operator^=`** | `bitmask<E>` | `bitmask<E>` | `bitmask<E>` | `bitmask<E>`

#### Unary bitwise operators

 | **`E`** | **`bitmask<E>`**
 | ------- | ----------------
**`operator~`** | `bitmask<E>` | `bitmask<E>`

#### Comparison operators

 | **`E, E`** | **`E`, `bitmask<E>`** | **`bitmask<E>`, `E`** | **`bitmask<E>`, `bitmask<E>`**
 | ---------- | --------------------- | --------------------- | ------------------------------
**`operator==`** | `bool` | `static_assert` | `static_assert` | `bool`
**`operator!=`** | `bool` | `static_assert` | `static_assert` | `bool`
