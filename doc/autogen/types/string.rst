.. rubric:: Methods

.. spicy:method:: string::encode string encode False bytes (charset: enum = hilti::Charset::UTF8)

    Converts the string into a binary representation encoded with the
    given character set.

.. rubric:: Operators

.. spicy:operator:: string::Equal bool t:string <sp> op:== <sp> t:string

    Compares two strings lexicographically.

.. spicy:operator:: string::Modulo string t:string <sp> op:% <sp> t:<any>

    Renders a printf-style format string.

.. spicy:operator:: string::Size uint<64> op:| t:string op:|

    Returns the number of characters the string contains.

.. spicy:operator:: string::Sum string t:string <sp> op:+ <sp> t:string

    Returns the concatenation of two strings.

.. spicy:operator:: string::Unequal bool t:string <sp> op:!= <sp> t:string

    Compares two strings lexicographically.

