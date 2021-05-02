.. rubric:: Operators

.. spicy:operator:: tuple::CustomAssign <tuple> t:(x,~...,~y) = t:<tuple>

    Assigns element-wise to the left-hand-side tuple

.. spicy:operator:: tuple::Equal bool t:tuple <sp> op:== <sp> t:tuple

    Compares two tuples element-wise.

.. spicy:operator:: tuple::Index <type~of~element> t:tuple[uint<64>]

    Extracts the tuple element at the given index. The index must be a
    constant unsigned integer.

.. spicy:operator:: tuple::Member <type~of~element> t:tuple <sp> op:. <sp> t:<id>

    Extracts the tuple element corresponding to the given ID.

.. spicy:operator:: tuple::Unequal bool t:tuple <sp> op:!= <sp> t:tuple

    Compares two tuples element-wise.

