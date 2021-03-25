.. rubric:: Operators

.. spicy:operator:: value_reference::Deref <dereferenced~type> op:* t:value_ref op:

    Returns the referenced instance, or throws an exception if none or
    expired.

.. spicy:operator:: value_reference::Equal bool t:value_ref <sp> op:== <sp> t:<no-doc> $commutative$

    Returns true if the values of both operands are equal.

.. spicy:operator:: value_reference::Unequal bool t:value_ref <sp> op:!= <sp> t:<no-doc> $commutative$

    Returns true if the values of both operands are not equal.

