.. rubric:: Methods

.. spicy:method:: set::clear set clear False void ()

    Removes all elements from the set.

.. rubric:: Operators

.. spicy:operator:: set::Add void add <sp> t:set[element]

    Adds an element to the set.

.. spicy:operator:: set::Begin <iterator> begin(<container>)

    Returns an iterator to the beginning of the container's content.

.. spicy:operator:: set::Delete void delete <sp> t:set[element]

    Removes an element from the set.

.. spicy:operator:: set::End <iterator> end(<container>)

    Returns an iterator to the end of the container's content.

.. spicy:operator:: set::Equal bool t:set <sp> op:== <sp> t:set

    Compares two sets element-wise.

.. spicy:operator:: set::In bool t:<any> <sp> op:in <sp> t:set

    Returns true if an element is part of the set.

.. spicy:operator:: set::InInv bool t:<any> <sp> op:!in <sp> t:set

    Performs the inverse of the corresponding ``in`` operation.

.. spicy:operator:: set::Size uint<64> op:| t:set op:|

    Returns the number of elements a set contains.

.. spicy:operator:: set::Unequal bool t:set <sp> op:!= <sp> t:set

    Compares two sets element-wise.

