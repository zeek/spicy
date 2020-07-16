.. rubric:: Iterator Operators

.. spicy:operator:: bytes::iterator::Deref uint<8> op:* t:iterator<bytes> op:

    Returns the character the iterator is pointing to.

.. spicy:operator:: bytes::iterator::Difference int<64> t:iterator<bytes> <sp> op:- <sp> t:iterator<bytes>

    Returns the number of bytes between the two iterators. The result will
    be negative if the second iterator points to a location before the
    first. The result is undefined if the iterators do not refer to the
    same bytes instance.

.. spicy:operator:: bytes::iterator::Equal bool t:iterator<bytes> <sp> op:== <sp> t:iterator<bytes>

    Compares the two positions. The result is undefined if they are not
    referring to the same bytes value.

.. spicy:operator:: bytes::iterator::Greater bool t:iterator<bytes> <sp> op:> <sp> t:iterator<bytes>

    Compares the two positions. The result is undefined if they are not
    referring to the same bytes value.

.. spicy:operator:: bytes::iterator::GreaterEqual bool t:iterator<bytes> <sp> op:>= <sp> t:iterator<bytes>

    Compares the two positions. The result is undefined if they are not
    referring to the same bytes value.

.. spicy:operator:: bytes::iterator::IncrPostfix iterator<bytes> op: t:iterator<bytes> op:++

    Advances the iterator by one byte, returning the previous position.

.. spicy:operator:: bytes::iterator::IncrPrefix iterator<bytes> op:++ t:iterator<bytes> op:

    Advances the iterator by one byte, returning the new position.

.. spicy:operator:: bytes::iterator::Lower bool t:iterator<bytes> <sp> op:< <sp> t:iterator<bytes>

    Compares the two positions. The result is undefined if they are not
    referring to the same bytes value.

.. spicy:operator:: bytes::iterator::LowerEqual bool t:iterator<bytes> <sp> op:<= <sp> t:iterator<bytes>

    Compares the two positions. The result is undefined if they are not
    referring to the same bytes value.

.. spicy:operator:: bytes::iterator::Sum iterator<bytes> t:iterator<bytes> <sp> op:+ <sp> t:uint<64> $commutative$

    Returns an iterator which is pointing the given number of bytes beyond
    the one passed in.

.. spicy:operator:: bytes::iterator::SumAssign iterator<bytes> t:iterator<bytes> <sp> op:+= <sp> t:uint<64>

    Advances the iterator by the given number of bytes.

.. spicy:operator:: bytes::iterator::Unequal bool t:iterator<bytes> <sp> op:!= <sp> t:iterator<bytes>

    Compares the two positions. The result is undefined if they are not
    referring to the same bytes value.

