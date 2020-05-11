.. rubric:: Operators

.. spicy:operator:: struct::HasMember bool t:struct <sp> op:?. <sp> t:<field>

    Returns true if the struct's field has a value assigned (not counting
    any ``&default``).

.. spicy:operator:: struct::Member <field~type> t:struct <sp> op:. <sp> t:<field>

    Retrieves the value of a struct's field. If the field does not have a
    value assigned, it returns its ``&default`` expression if that has
    been defined; otherwise it triggers an exception.

.. spicy:operator:: struct::TryMember <field~type> t:struct <sp> op:.? <sp> t:<field>

    Retrieves the value of a struct's field. If the field does not have a
    value assigned, it returns its ``&default`` expression if that has
    been defined; otherwise it signals a special non-error exception to
    the host application (which will normally still lead to aborting
    execution, similar to the standard dereference operator, unless the
    host application specifically handles this exception differently).

.. spicy:operator:: struct::Unset void unset <sp> t:struct.<field>

    Clears an optional field.

