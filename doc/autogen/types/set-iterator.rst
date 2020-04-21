.. rubric:: Iterator Operators

.. spicy:operator:: set::iterator::Deref <dereferenced~type> op:* t:<no-type> op:

    Returns the set element that the iterator refers to.

.. spicy:operator:: set::iterator::Equal bool t:<no-type> <sp> op:== <sp> t:iterator<set>

    Returns true if two sets iterators refer to the same location.

.. spicy:operator:: set::iterator::IncrPostfix iterator<set> op: t:<no-type> op:++

    Advances the iterator by one set element, returning the previous
    position.

.. spicy:operator:: set::iterator::IncrPrefix iterator<set> op:++ t:<no-type> op:

    Advances the iterator by one set element, returning the new position.

.. spicy:operator:: set::iterator::Unequal bool t:<no-type> <sp> op:!= <sp> t:iterator<set>

    Returns true if two sets iterators refer to different locations.

