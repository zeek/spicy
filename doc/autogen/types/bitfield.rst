.. rubric:: Operators

.. spicy:operator:: bitfield::HasMember bool t:bitfield <sp> op:?. <sp> t:<field>

    Returns true if the bitfield's element has a value.

.. spicy:operator:: bitfield::Member <field~type> t:bitfield <sp> op:. <sp> t:<attribute>

    Retrieves the value of a bitfield's attribute. This is the value of
    the corresponding bits inside the underlying integer value, shifted to
    the very right.

