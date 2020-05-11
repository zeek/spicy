.. rubric:: Methods

.. spicy:method:: map::clear map clear False void ()

    Removes all elements from the map.

.. spicy:method:: map::get map get False <type~of~element> (key: <any>, [ default: <any> ])

    Returns the map's element for the given key. If the key does not
    exist, returns the default value if provided; otherwise throws a
    runtime error.

.. rubric:: Operators

.. spicy:operator:: map::Delete void delete <sp> t:map[<type~of~key>]

    Removes an element from the map.

.. spicy:operator:: map::Equal bool t:map <sp> op:== <sp> t:map

    Compares two maps element-wise.

.. spicy:operator:: map::In bool t:<any> <sp> op:in <sp> t:map

    Returns true if an element is part of the map.

.. spicy:operator:: map::Index <type~of~element> t:map[<any>]

    Returns the map's element for the given key.

.. spicy:operator:: map::Index <type~of~element> t:map[<any>]

    Returns the map's element for the given key. The key must exists,
    otherwise the operation will throw a runtime error.

.. spicy:operator:: map::Size uint<64> op:| t:map op:|

    Returns the number of elements a map contains.

.. spicy:operator:: map::Unequal bool t:map <sp> op:!= <sp> t:map

    Compares two maps element-wise.

