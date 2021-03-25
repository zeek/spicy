.. rubric:: Operators

.. spicy:operator:: union_::Equal bool t:union <sp> op:== <sp> t:union

    Compares two unions element-wise.

.. spicy:operator:: union_::HasMember bool t:union <sp> op:?. <sp> t:<field>

    Returns true if the union's field is set.

.. spicy:operator:: union_::Member <field~type> t:union <sp> op:. <sp> t:<field>

    Retrieves the value of a union's field. If the union does not have the
    field set, this triggers an exception unless the value is only being
    assigned to.

.. spicy:operator:: union_::Member <field~type> t:union <sp> op:. <sp> t:<field>

    Retrieves the value of a union's field. If the union does not have the
    field set, this triggers an exception.

.. spicy:operator:: union_::Unequal bool t:union <sp> op:!= <sp> t:union

    Compares two unions element-wise.

