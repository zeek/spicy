.. rubric:: Methods

.. spicy:method:: unit::backtrack unit backtrack False void ()

    Aborts parsing at the current position and returns back to the most
    recent ``&try`` attribute. Turns into a parse error if there's no
    ``&try`` in scope.

.. spicy:method:: unit::connect_filter unit connect_filter False void (filter: strong_ref<unit>)

    Connects a separate filter unit to transform the unit's input
    transparently before parsing. The filter unit will see the original
    input, and this unit will receive everything the filter passes on
    through `forward()`.

    Filters can be connected only before a unit's parsing begins. The
    latest possible point is from inside the target unit's `%init` hook.

.. spicy:method:: unit::forward unit forward False void (inout data: bytes)

    If the unit is connected as a filter to another one, this method
    forwards transformed input over to that other one to parse. If the
    unit is not connected, this method will silently discard the data.

.. spicy:method:: unit::forward_eod unit forward_eod False void ()

    If the unit is connected as a filter to another one, this method
    signals that other one that end of its input has been reached. If the
    unit is not connected, this method will not do anything.

.. spicy:method:: unit::input unit input False iterator<stream> ()

    Returns an iterator referring to the input location where the current
    unit has begun parsing. If this method is called before the units
    parsing has begun, it will throw a runtime exception. Once available,
    the input position will remain accessible for the unit's entire life
    time.

    Usage of this method requires the unit to be declared with the
    `%random-access` property.

.. spicy:method:: unit::offset unit offset False uint<64> ()

    Returns the offset of the current location in the input stream
    relative to the unit's start. If executed from inside a field hook,
    the offset will represent the first byte that the field has been
    parsed from. If this method is called before the unit's parsing has
    begun, it will throw a runtime exception. Once parsing has started,
    the offset will remain available for the unit's entire life time.

    Usage of this method requires the unit to be declared with the
    `%random-access` property.

.. spicy:method:: unit::set_input unit set_input False void (i: iterator<stream>)

    Moves the current parsing position to *i*. The new position *i* must
    be located inside the range between the first bytes of the current
    unit (i.e., the result of ``self.input()``) and the current parsing
    position. If the new position is outside of that range, the method
    will throw a runtime exception.

    Usage of this method requires the unit to be declared with the
    `%random-access` property.

