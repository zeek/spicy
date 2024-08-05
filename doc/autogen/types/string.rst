.. rubric:: Methods

.. spicy:method:: string::encode string encode False bytes ([ charset: spicy::Charset = hilti::Charset::UTF8 ])

    Converts the string into a binary representation encoded with the
    given character set.

.. spicy:method:: string::split string split False vector<string> ([ sep: string ])

    Splits the string value at each occurrence of *sep* and returns a
    vector containing the individual pieces, with all separators removed.
    If the separator is not found, or if the separator is empty, the
    returned vector will have the whole string value as its single
    element. If the separator is not given, the split will occur at
    sequences of white spaces.

.. spicy:method:: string::split1 string split1 False tuple<string,~string> ([ sep: string ])

    Splits the string value at the first occurrence of *sep* and returns
    the two parts as a 2-tuple, with the separator removed. If the
    separator is not found, the returned tuple will have the whole string
    value as its first element and an empty value as its second element.
    If the separator is empty, the returned tuple will have an empty first
    element and the whole string value as its second element. If the
    separator is not provided, the split will occur at the first sequence
    of white spaces.

.. spicy:method:: string::starts_with string starts_with False bool (prefix: string)

    Returns true if the string value starts with *prefix*.

.. rubric:: Operators

.. spicy:operator:: string::Equal bool t:string <sp> op:== <sp> t:string

    Compares two strings lexicographically.

.. spicy:operator:: string::Modulo string t:string <sp> op:% <sp> t:<any>

    Renders a printf-style format string.

.. spicy:operator:: string::Size uint<64> op:| t:string op:|

    Returns the number of characters the string contains.

.. spicy:operator:: string::Sum string t:string <sp> op:+ <sp> t:string

    Returns the concatenation of two strings.

.. spicy:operator:: string::SumAssign string t:string <sp> op:+= <sp> t:string

    Appends the second string to the first.

.. spicy:operator:: string::Unequal bool t:string <sp> op:!= <sp> t:string

    Compares two strings lexicographically.

