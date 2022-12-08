.. rubric:: Methods

.. spicy:method:: stream::at stream at False iterator<stream> (i: uint<64>)

    Returns an iterator representing the offset *i* inside the stream
    value.

.. spicy:method:: stream::freeze stream freeze False void ()

    Freezes the stream value. Once frozen, one cannot append any more data
    to a frozen stream value (unless it gets unfrozen first). If the value
    is already frozen, the operation does not change anything.

.. spicy:method:: stream::is_frozen stream is_frozen False bool ()

    Returns true if the stream value has been frozen.

.. spicy:method:: stream::trim stream trim False void (inout i: iterator<stream>)

    Trims the stream value by removing all data from its beginning up to
    (but not including) the position *i*. The iterator *i* will remain
    valid afterwards and will still point to the same location, which will
    now be the beginning of the stream's value. All existing iterators
    pointing to *i* or beyond will remain valid and keep their offsets as
    well. The effect of this operation is undefined if *i* does not
    actually refer to a location inside the stream value. Trimming is
    permitted even on frozen values.

.. spicy:method:: stream::unfreeze stream unfreeze False void ()

    Unfreezes the stream value. A unfrozen stream value can be further
    modified. If the value is already unfrozen (which is the default), the
    operation does not change anything.

.. rubric:: Operators

.. spicy:operator:: stream::Begin <iterator> begin(<container>)

    Returns an iterator to the beginning of the container's content.

.. spicy:operator:: stream::Call stream stream(bytes)

    Creates a stream instance preinitialized with the given data.

.. spicy:operator:: stream::End <iterator> end(<container>)

    Returns an iterator to the end of the container's content.

.. spicy:operator:: stream::Size uint<64> op:| t:stream op:|

    Returns the number of stream the value contains.

.. spicy:operator:: stream::SumAssign stream t:stream <sp> op:+= <sp> t:bytes

    Concatenates data to the stream.

.. spicy:operator:: stream::SumAssign stream t:stream <sp> op:+= <sp> t:view<stream>

    Concatenates another stream's view to the target stream.

.. spicy:operator:: stream::Unequal bool t:stream <sp> op:!= <sp> t:stream

    Compares two stream values lexicographically.

