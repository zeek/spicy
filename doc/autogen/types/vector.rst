.. rubric:: Methods

.. spicy:method:: vector::assign vector assign False void (i: uint<64>, x: <any>)

    Assigns *x* to the *i*th element of the vector. If the vector contains
    less than *i* elements a sufficient number of default-initialized
    elements is added to carry out the assignment.

.. spicy:method:: vector::at vector at False <iterator> (i: uint<64>)

    Returns an iterator referring to the element at vector index *i*.

.. spicy:method:: vector::back vector back False <type~of~element> ()

    Returns the last element of the vector. It throws an exception if the
    vector is empty.

.. spicy:method:: vector::front vector front False <type~of~element> ()

    Returns the first element of the vector. It throws an exception if the
    vector is empty.

.. spicy:method:: vector::pop_back vector pop_back False void ()

    Removes the last element from the vector, which must be non-empty.

.. spicy:method:: vector::push_back vector push_back False void (x: <any>)

    Appends *x* to the end of the vector.

.. spicy:method:: vector::reserve vector reserve False void (n: uint<64>)

    Reserves space for at least *n* elements. This operation does not
    change the vector in any observable way but provides a hint about the
    size that will be needed.

.. spicy:method:: vector::resize vector resize False void (n: uint<64>)

    Resizes the vector to hold exactly *n* elements. If *n* is larger than
    the current size, the new slots are filled with default values. If *n*
    is smaller than the current size, the excessive elements are removed.

.. spicy:method:: vector::sub vector sub False vector (begin: uint<64>, end: uint<64>)

    Extracts a subsequence of vector elements spanning from index *begin*
    to (but not including) index *end*.

.. spicy:method:: vector::sub vector sub False vector (end: uint<64>)

    Extracts a subsequence of vector elements spanning from the beginning
    to (but not including) the index *end* as a new vector.

.. rubric:: Operators

.. spicy:operator:: vector::Begin <iterator> begin(<container>)

    Returns an iterator to the beginning of the container's content.

.. spicy:operator:: vector::End <iterator> end(<container>)

    Returns an iterator to the end of the container's content.

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

