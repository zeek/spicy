.. rubric:: Methods

.. spicy:method:: bytes::at bytes at False iterator<bytes> (i: uint<64>)

    Returns an iterator representing the offset *i* inside the bytes
    value.

.. spicy:method:: bytes::decode bytes decode False string (charset: enum = hilti::Charset::UTF8, errors: enum = hilti::DecodeErrorStrategy::REPLACE)

    Interprets the ``bytes`` as representing an binary string encoded with
    the given character set, and converts it into a UTF8 string. If data
    is encountered that *charset* or UTF* cannot represent, it's handled
    according to the *errors* strategy.

.. spicy:method:: bytes::find bytes find False tuple<bool,~iterator<bytes>> (needle: bytes)

    Searches *needle* in the value's content. Returns a tuple of a boolean
    and an iterator. If *needle* was found, the boolean will be true and
    the iterator will point to its first occurrence. If *needle* was not
    found, the boolean will be false and the iterator will point to the
    last position so that everything before it is guaranteed to not
    contain even a partial match of *needle*. Note that for a simple
    yes/no result, you should use the ``in`` operator instead of this
    method, as it's more efficient.

.. spicy:method:: bytes::join bytes join False bytes (inout parts: vector)

    Returns the concatenation of all elements in the *parts* list rendered
    as printable strings. The portions will be separated by the bytes
    value to which this method is invoked as a member.

.. spicy:method:: bytes::lower bytes lower False bytes (charset: enum = hilti::Charset::UTF8, errors: enum = hilti::DecodeErrorStrategy::REPLACE)

    Returns a lower-case version of the bytes value, assuming it is
    encoded in character set *charset*. If data is encountered that
    *charset* cannot represent, it's handled according to the *errors*
    strategy.

.. spicy:method:: bytes::match bytes match False result<bytes> (regex: regexp, [ group: uint<64> ])

    Matches the ``bytes`` object against the regular expression *regex*.
    Returns the matching part or, if *group* is given, then the
    corresponding subgroup. The expression is considered anchored to the
    beginning of the data.

.. spicy:method:: bytes::split bytes split False vector<bytes> ([ sep: bytes ])

    Splits the bytes value at each occurrence of *sep* and returns a
    vector containing the individual pieces, with all separators removed.
    If the separator is not found, the returned vector will have the whole
    bytes value as its single element. If the separator is not given, or
    empty, the split will take place at sequences of white spaces.

.. spicy:method:: bytes::split1 bytes split1 False tuple<bytes,~bytes> ([ sep: bytes ])

    Splits the bytes value at the first occurrence of *sep* and returns
    the two parts as a 2-tuple, with the separator removed. If the
    separator is not found, the returned tuple will have the whole bytes
    value as its first element and an empty value as its second element.
    If the separator is not given, or empty, the split will take place at
    the first sequence of white spaces.

.. spicy:method:: bytes::starts_with bytes starts_with False bool (b: bytes)

    Returns true if the bytes value starts with *b*.

.. spicy:method:: bytes::strip bytes strip False bytes ([ side: spicy::Side ], [ set: bytes ])

    Removes leading and/or trailing sequences of all characters in *set*
    from the bytes value. If *set* is not given, removes all white spaces.
    If *side* is given, it indicates which side of the value should be
    stripped; ``Side::Both`` is the default if not given.

.. spicy:method:: bytes::sub bytes sub False bytes (begin: uint<64>, end: uint<64>)

    Returns the subsequence from offset *begin* to (but not including)
    offset *end*.

.. spicy:method:: bytes::sub bytes sub False bytes (inout begin: iterator<bytes>, inout end: iterator<bytes>)

    Returns the subsequence from *begin* to (but not including) *end*.

.. spicy:method:: bytes::sub bytes sub False bytes (inout end: iterator<bytes>)

    Returns the subsequence from the value's beginning to (but not
    including) *end*.

.. spicy:method:: bytes::to_int bytes to_int False int<64> ([ base: uint<64> ])

    Interprets the data as representing an ASCII-encoded number and
    converts that into a signed integer, using a base of *base*. *base*
    must be between 2 and 36. If *base* is not given, the default is 10.

.. spicy:method:: bytes::to_int bytes to_int False int<64> (byte_order: enum)

    Interprets the ``bytes`` as representing an binary number encoded with
    the given byte order, and converts it into signed integer.

.. spicy:method:: bytes::to_time bytes to_time False time ([ base: uint<64> ])

    Interprets the ``bytes`` as representing a number of seconds since the
    epoch in the form of an ASCII-encoded number, and converts it into a
    time value using a base of *base*. If *base* is not given, the default
    is 10.

.. spicy:method:: bytes::to_time bytes to_time False time (byte_order: enum)

    Interprets the ``bytes`` as representing as number of seconds since
    the epoch in the form of an binary number encoded with the given byte
    order, and converts it into a time value.

.. spicy:method:: bytes::to_uint bytes to_uint False uint<64> ([ base: uint<64> ])

    Interprets the data as representing an ASCII-encoded number and
    converts that into an unsigned integer, using a base of *base*. *base*
    must be between 2 and 36. If *base* is not given, the default is 10.

.. spicy:method:: bytes::to_uint bytes to_uint False uint<64> (byte_order: enum)

    Interprets the ``bytes`` as representing an binary number encoded with
    the given byte order, and converts it into an unsigned integer.

.. spicy:method:: bytes::upper bytes upper False bytes (charset: enum = hilti::Charset::UTF8, errors: enum = hilti::DecodeErrorStrategy::REPLACE)

    Returns an upper-case version of the bytes value, assuming it is
    encoded in character set *charset*. If data is encountered that
    *charset* cannot represent, it's handled according to the *errors*
    strategy.

.. rubric:: Operators

.. spicy:operator:: bytes::Begin <iterator> begin(<container>)

    Returns an iterator to the beginning of the container's content.

.. spicy:operator:: bytes::End <iterator> end(<container>)

    Returns an iterator to the end of the container's content.

.. spicy:operator:: bytes::Equal bool t:bytes <sp> op:== <sp> t:bytes

    Compares two bytes values lexicographically.

.. spicy:operator:: bytes::Greater bool t:bytes <sp> op:> <sp> t:bytes

    Compares two bytes values lexicographically.

.. spicy:operator:: bytes::GreaterEqual bool t:bytes <sp> op:>= <sp> t:bytes

    Compares two bytes values lexicographically.

.. spicy:operator:: bytes::In bool t:bytes <sp> op:in <sp> t:bytes

    Returns true if the right-hand-side value contains the left-hand-side
    value as a subsequence.

.. spicy:operator:: bytes::InInv bool t:bytes <sp> op:!in <sp> t:bytes

    Performs the inverse of the corresponding ``in`` operation.

.. spicy:operator:: bytes::Lower bool t:bytes <sp> op:< <sp> t:bytes

    Compares two bytes values lexicographically.

.. spicy:operator:: bytes::LowerEqual bool t:bytes <sp> op:<= <sp> t:bytes

    Compares two bytes values lexicographically.

.. spicy:operator:: bytes::Size uint<64> op:| t:bytes op:|

    Returns the number of bytes the value contains.

.. spicy:operator:: bytes::Sum bytes t:bytes <sp> op:+ <sp> t:bytes

    Returns the concatenation of two bytes values.

.. spicy:operator:: bytes::SumAssign bytes t:bytes <sp> op:+= <sp> t:bytes

    Appends one bytes value to another.

.. spicy:operator:: bytes::SumAssign bytes t:bytes <sp> op:+= <sp> t:uint<8>

    Appends a single byte to the data.

.. spicy:operator:: bytes::SumAssign bytes t:bytes <sp> op:+= <sp> t:view<stream>

    Appends a view of stream data to a bytes instance.

.. spicy:operator:: bytes::Unequal bool t:bytes <sp> op:!= <sp> t:bytes

    Compares two bytes values lexicographically.

