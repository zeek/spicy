.. rubric:: Iterator Methods

.. spicy:method:: stream::iterator::is_frozen iterator<stream> is_frozen False bool ()

    Returns whether the stream value that the iterator refers to has been
    frozen.

.. spicy:method:: stream::iterator::offset iterator<stream> offset False uint<64> ()

    Returns the offset of the byte that the iterator refers to relative to
    the beginning of the underlying stream value.

.. rubric:: Iterator Operators

.. spicy:operator:: stream::iterator::Deref uint<64> op:* t:iterator<stream> op:

    Returns the character the iterator is pointing to.

.. spicy:operator:: stream::iterator::Difference int<64> t:iterator<stream> <sp> op:- <sp> t:iterator<stream>

    Returns the number of stream between the two iterators. The result
    will be negative if the second iterator points to a location before
    the first. The result is undefined if the iterators do not refer to
    the same stream instance.

.. spicy:operator:: stream::iterator::Equal bool t:iterator<stream> <sp> op:== <sp> t:iterator<stream>

    Compares the two positions. The result is undefined if they are not
    referring to the same stream value.

.. spicy:operator:: stream::iterator::Greater bool t:iterator<stream> <sp> op:> <sp> t:iterator<stream>

    Compares the two positions. The result is undefined if they are not
    referring to the same stream value.

.. spicy:operator:: stream::iterator::GreaterEqual bool t:iterator<stream> <sp> op:>= <sp> t:iterator<stream>

    Compares the two positions. The result is undefined if they are not
    referring to the same stream value.

.. spicy:operator:: stream::iterator::IncrPostfix iterator<stream> op: t:iterator<stream> op:++

    Advances the iterator by one byte, returning the previous position.

.. spicy:operator:: stream::iterator::IncrPrefix iterator<stream> op:++ t:iterator<stream> op:

    Advances the iterator by one byte, returning the new position.

.. spicy:operator:: stream::iterator::Lower bool t:iterator<stream> <sp> op:< <sp> t:iterator<stream>

    Compares the two positions. The result is undefined if they are not
    referring to the same stream value.

.. spicy:operator:: stream::iterator::LowerEqual bool t:iterator<stream> <sp> op:<= <sp> t:iterator<stream>

    Compares the two positions. The result is undefined if they are not
    referring to the same stream value.

.. spicy:operator:: stream::iterator::Sum iterator<stream> t:iterator<stream> <sp> op:+ <sp> t:uint<64> $commutative$

    Advances the iterator by the given number of stream.

.. spicy:operator:: stream::iterator::SumAssign iterator<stream> t:iterator<stream> <sp> op:+= <sp> t:uint<64>

    Advances the iterator by the given number of stream.

.. spicy:operator:: stream::iterator::Unequal bool t:iterator<stream> <sp> op:!= <sp> t:iterator<stream>

    Compares the two positions. The result is undefined if they are not
    referring to the same stream value.

