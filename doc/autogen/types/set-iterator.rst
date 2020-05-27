.. rubric:: Iterator Operators

.. spicy:operator:: set::iterator::Deref <dereferenced~type> op:* t:iterator<set> op:

    Returns the set element that the iterator refers to.

.. spicy:operator:: set::iterator::Equal bool t:iterator<set> <sp> op:== <sp> t:iterator<set>

    Returns true if two sets iterators refer to the same location.

.. spicy:operator:: set::iterator::IncrPostfix iterator<set> op: t:iterator<set> op:++

    Advances the iterator by one set element, returning the previous
    position.

.. spicy:operator:: set::iterator::IncrPrefix iterator<set> op:++ t:iterator<set> op:

    Advances the iterator by one set element, returning the new position.

.. spicy:operator:: set::iterator::Unequal bool t:iterator<set> <sp> op:!= <sp> t:iterator<set>

    Returns true if two sets iterators refer to different locations.

