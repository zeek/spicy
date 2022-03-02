.. rubric:: View Methods

.. spicy:method:: stream::view::advance view<stream> advance False view<stream> (i: uint<64>)

    Advances the view's starting position by *i* stream, returning the new
    view.

.. spicy:method:: stream::view::advance view<stream> advance False view<stream> (inout i: iterator<stream>)

    Advances the view's starting position to a given iterator *i*,
    returning the new view. The iterator must be referring to the same
    stream values as the view, and it must be equal or ahead of the view's
    starting position.

.. spicy:method:: stream::view::advance_to_next_data view<stream> advance_to_next_data False view<stream> ()

    Advances the view's starting position to the next non-gap position.
    This always advances the input by at least one byte.

.. spicy:method:: stream::view::at view<stream> at False iterator<stream> (i: uint<64>)

    Returns an iterator representing the offset *i* inside the view.

.. spicy:method:: stream::view::find view<stream> find False tuple<bool,~iterator<stream>> (needle: bytes)

    Searches *needle* inside the view's content. Returns a tuple of a
    boolean and an iterator. If *needle* was found, the boolean will be
    true and the iterator will point to its first occurrence. If *needle*
    was not found, the boolean will be false and the iterator will point
    to the last position so that everything before that is guaranteed to
    not contain even a partial match of *needle* (in other words: one can
    trim until that position and then restart the search from there if
    more data gets appended to the underlying stream value). Note that for
    a simple yes/no result, you should use the ``in`` operator instead of
    this method, as it's more efficient.

.. spicy:method:: stream::view::limit view<stream> limit False view<stream> (i: uint<64>)

    Returns a new view that keeps the current start but cuts off the end
    *i* characters from that beginning. The returned view will not be able
    to expand any further.

.. spicy:method:: stream::view::offset view<stream> offset False uint<64> ()

    Returns the offset of the view's starting position within the
    associated stream value.

.. spicy:method:: stream::view::starts_with view<stream> starts_with False bool (b: bytes)

    Returns true if the view starts with *b*.

.. spicy:method:: stream::view::sub view<stream> sub False view<stream> (begin: uint<64>, end: uint<64>)

    Returns a new view of the subsequence from offset *begin* to (but not
    including) offset *end*. The offsets are relative to the beginning of
    the view.

.. spicy:method:: stream::view::sub view<stream> sub False view<stream> (inout begin: iterator<stream>, inout end: iterator<stream>)

    Returns a new view of the subsequence from *begin* up to (but not
    including) *end*.

.. spicy:method:: stream::view::sub view<stream> sub False view<stream> (inout end: iterator<stream>)

    Returns a new view of the subsequence from the beginning of the stream
    up to (but not including) *end*.

.. rubric:: View Operators

.. spicy:operator:: stream::view::Equal bool t:view<stream> <sp> op:== <sp> t:bytes $commutative$

    Compares a stream view and a bytes instance lexicographically.

.. spicy:operator:: stream::view::Equal bool t:view<stream> <sp> op:== <sp> t:view<stream>

    Compares the views lexicographically.

.. spicy:operator:: stream::view::In bool t:bytes <sp> op:in <sp> t:view<stream>

    Returns true if the right-hand-side bytes contains the left-hand-side
    view as a subsequence.

.. spicy:operator:: stream::view::In bool t:view<stream> <sp> op:in <sp> t:bytes

    Returns true if the right-hand-side view contains the left-hand-side
    bytes as a subsequence.

.. spicy:operator:: stream::view::InInv bool t:bytes <sp> op:!in <sp> t:view<stream>

    Performs the inverse of the corresponding ``in`` operation.

.. spicy:operator:: stream::view::InInv bool t:view<stream> <sp> op:!in <sp> t:bytes

    Performs the inverse of the corresponding ``in`` operation.

.. spicy:operator:: stream::view::Size uint<64> op:| t:view<stream> op:|

    Returns the number of stream the view contains.

.. spicy:operator:: stream::view::Unequal bool t:view<stream> <sp> op:!= <sp> t:bytes $commutative$

    Compares a stream view and a bytes instance lexicographically.

.. spicy:operator:: stream::view::Unequal bool t:view<stream> <sp> op:!= <sp> t:view<stream>

    Compares two views lexicographically.

