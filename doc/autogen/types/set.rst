.. rubric:: Methods

.. spicy:method:: set::clear set clear False void ()

    Removes all elements from the set.

.. rubric:: Operators

.. spicy:operator:: set::Add void add t:set

    Adds an element to the set.

.. spicy:operator:: set::Delete void delete t:set

    Removes an element from the set.

.. spicy:operator:: set::Equal bool t:set <sp> op:== <sp> t:set

    Compares two sets element-wise.

.. spicy:operator:: set::In bool t:<any> <sp> op:in <sp> t:set

    Returns true if an element is part of the set.

.. spicy:operator:: set::Size uint<64> op:| t:set op:|

    Returns the number of elements a set contains.

.. spicy:operator:: set::Unequal bool t:set <sp> op:!= <sp> t:set

    Compares two sets element-wise.

