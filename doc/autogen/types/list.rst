.. rubric:: Operators

.. spicy:operator:: list::Begin <iterator> begin(<container>)

    Returns an iterator to the beginning of the container's content.

.. spicy:operator:: list::End <iterator> end(<container>)

    Returns an iterator to the end of the container's content.

.. spicy:operator:: list::Equal bool t:list <sp> op:== <sp> t:list

    Compares two lists element-wise.

.. spicy:operator:: list::Size uint<64> op:| t:list op:|

    Returns the number of elements a list contains.

.. spicy:operator:: list::Unequal bool t:list <sp> op:!= <sp> t:list

    Compares two lists element-wise.

