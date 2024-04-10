.. rubric:: Operators

.. spicy:operator:: strong_reference::Deref <dereferenced~type> op:* t:(T&) op:

    Returns the referenced instance, or throws an exception if none or
    expired.

.. spicy:operator:: strong_reference::Equal bool t:T& <sp> op:== <sp> t:T&

    Returns true if both operands reference the same instance.

.. spicy:operator:: strong_reference::Unequal bool t:T& <sp> op:!= <sp> t:T&

    Returns true if the two operands reference different instances.

