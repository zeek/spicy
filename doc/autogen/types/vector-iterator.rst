.. rubric:: Iterator Operators

.. spicy:operator:: vector::iterator::Deref <dereferenced~type> op:* t:iterator<vector> op:

    Returns the vector element that the iterator refers to.

.. spicy:operator:: vector::iterator::Equal bool t:iterator<vector> <sp> op:== <sp> t:iterator<vector>

    Returns true if two vector iterators refer to the same location.

.. spicy:operator:: vector::iterator::IncrPostfix iterator<vector> op: t:iterator<vector> op:++

    Advances the iterator by one vector element, returning the previous
    position.

.. spicy:operator:: vector::iterator::IncrPrefix iterator<vector> op:++ t:iterator<vector> op:

    Advances the iterator by one vector element, returning the new
    position.

.. spicy:operator:: vector::iterator::Unequal bool t:iterator<vector> <sp> op:!= <sp> t:iterator<vector>

    Returns true if two vector iterators refer to different locations.

