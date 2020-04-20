.. rubric:: Methods

.. spicy:method:: vector::back vector back False <type~of~element> ()

    Returns the last element of the vector. It throws an exception if the
    vector is empty.

.. spicy:method:: vector::front vector front False <type~of~element> ()

    Returns the first element of the vector. It throws an exception if the
    vector is empty.

.. spicy:method:: vector::push_back vector push_back False void (x: <any>)

    Appends *x* to the end of the vector.

.. spicy:method:: vector::reserve vector reserve False void (n: uint<64>)

    Reserves space for at least *n* elements. This operation does not
    change the vector in any observable way but provides a hint about the
    size that will be needed.

.. rubric:: Operators

.. spicy:operator:: vector::Equal bool t:vector <sp> op:== <sp> t:vector

    Compares two vectors element-wise.

.. spicy:operator:: vector::Index <type~of~element> t:vector[uint<64>]

    Returns the vector element at the given index.

.. spicy:operator:: vector::Size uint<64> op:| t:vector op:|

    Returns the number of elements a vector contains.

.. spicy:operator:: vector::Sum vector t:vector <sp> op:+ <sp> t:vector

    Returns the concatenation of two vectors.

.. spicy:operator:: vector::SumAssign vector t:vector <sp> op:+= <sp> t:vector

    Concatenates another vector to the vector.

.. spicy:operator:: vector::Unequal bool t:vector <sp> op:!= <sp> t:vector

    Compares two vectors element-wise.

