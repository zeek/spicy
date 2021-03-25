.. rubric:: Operators

.. spicy:operator:: weak_reference::Deref <dereferenced~type> op:* t:weak_ref op:

    Returns the referenced instance, or throws an exception if none or
    expired.

.. spicy:operator:: weak_reference::Equal bool t:weak_ref <sp> op:== <sp> t:<no-doc> $commutative$

    Returns true if both operands reference the same instance.

.. spicy:operator:: weak_reference::Unequal bool t:weak_ref <sp> op:!= <sp> t:<no-doc> $commutative$

    Returns true if the two operands reference different instances.

