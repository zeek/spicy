.. rubric:: Iterator Operators

.. spicy:operator:: list::iterator::Deref <dereferenced~type> op:* t:iterator<list> op:

    Returns the list element that the iterator refers to.

.. spicy:operator:: list::iterator::Equal bool t:iterator<list> <sp> op:== <sp> t:iterator<list>

    Returns true if two lists iterators refer to the same location.

.. spicy:operator:: list::iterator::IncrPostfix iterator<list> op: t:iterator<list> op:++

    Advances the iterator by one list element, returning the previous
    position.

.. spicy:operator:: list::iterator::IncrPrefix iterator<list> op:++ t:iterator<list> op:

    Advances the iterator by one list element, returning the new position.

.. spicy:operator:: list::iterator::Unequal bool t:iterator<list> <sp> op:!= <sp> t:iterator<list>

    Returns true if two lists iterators refer to different locations.

