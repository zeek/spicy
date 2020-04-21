.. rubric:: Iterator Operators

.. spicy:operator:: map::iterator::Deref <dereferenced~type> op:* t:<no-type> op:

    Returns the map element that the iterator refers to.

.. spicy:operator:: map::iterator::Equal bool t:<no-type> <sp> op:== <sp> t:iterator<map>

    Returns true if two map iterators refer to the same location.

.. spicy:operator:: map::iterator::IncrPostfix iterator<map> op: t:<no-type> op:++

    Advances the iterator by one map element, returning the previous
    position.

.. spicy:operator:: map::iterator::IncrPrefix iterator<map> op:++ t:<no-type> op:

    Advances the iterator by one map element, returning the new position.

.. spicy:operator:: map::iterator::Unequal bool t:<no-type> <sp> op:!= <sp> t:iterator<map>

    Returns true if two map iterators refer to different locations.

