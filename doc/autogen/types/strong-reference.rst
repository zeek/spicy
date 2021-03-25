.. rubric:: Operators

.. spicy:operator:: strong_reference::Deref <dereferenced~type> op:* t:strong_ref op:

    Returns the referenced instance, or throws an exception if none or
    expired.

.. spicy:operator:: strong_reference::Equal bool t:strong_ref <sp> op:== <sp> t:<no-doc> $commutative$

    Returns true if both operands reference the same instance.

.. spicy:operator:: strong_reference::Unequal bool t:strong_ref <sp> op:!= <sp> t:<no-doc> $commutative$

    Returns true if the two operands reference different instances.

