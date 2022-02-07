.. rubric:: Methods

.. spicy:method:: unit::backtrack unit backtrack False void ()

    Aborts parsing at the current position and returns back to the most
    recent ``&try`` attribute. Turns into a parse error if there's no
    ``&try`` in scope.

.. spicy:method:: unit::connect_filter unit connect_filter False void (filter: strong_ref<unit>)

    Connects a separate filter unit to transform the unit's input
    transparently before parsing. The filter unit will see the original
    input, and this unit will receive everything the filter passes on
    through ``forward()``.

    Filters can be connected only before a unit's parsing begins. The
    latest possible point is from inside the target unit's ``%init`` hook.

.. spicy:method:: unit::context unit context False <context>& ()

    Returns a reference to the ``%context`` instance associated with the
    unit.

.. spicy:method:: unit::find unit find False optional<iterator<stream>> (needle: bytes, [ dir: enum ], [ start: iterator<stream> ])

    Searches a *needle* pattern inside the input region defined by where
    the unit began parsing and its current parsing position. If executed
    from inside a field hook, the current parasing position will represent
    the *first* byte that the field has been parsed from. By default, the
    search will start at the beginning of that region and scan forward. If
    the direction is ``spicy::Direcction::Backward``, the search will
    start at the end of the region and scan backward. In either case, a
    starting position can also be explicitly given, but must lie inside
    the same region.

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

.. spicy:method:: unit::offset unit offset False uint<64> ()

    Returns the offset of the current location in the input stream
    relative to the unit's start. If executed from inside a field hook,
    the offset will represent the first byte that the field has been
    parsed from. If this method is called before the unit's parsing has
    begun, it will throw a runtime exception. Once parsing has started,
    the offset will remain available for the unit's entire life time.

.. spicy:method:: unit::position unit position False iterator<stream> ()

    Returns an iterator to the current position in the unit's input
    stream. If executed from inside a field hook, the position will
    represent the first byte that the field has been parsed from. If this
    method is called before the unit's parsing has begun, it will throw a
    runtime exception.

.. spicy:method:: unit::set_input unit set_input False void (i: iterator<stream>)

    Moves the current parsing position to *i*. The iterator *i* must be
    into the input of the current unit, or the method will throw a runtime
    exception.

.. rubric:: Operators

.. spicy:operator:: unit::HasMember bool t:unit <sp> op:?. <sp> t:<field>

    Returns true if the unit's field has a value assigned (not counting
    any ``&default``).

.. spicy:operator:: unit::Member <field~type> t:unit <sp> op:. <sp> t:<field>

    Retrieves the value of a unit's field. If the field does not have a
    value assigned, it returns its ``&default`` expression if that has
    been defined; otherwise it triggers an exception.

.. spicy:operator:: unit::TryMember <field~type> t:unit <sp> op:.? <sp> t:<field>

    Retrieves the value of a unit's field. If the field does not have a
    value assigned, it returns its ``&default`` expression if that has
    been defined; otherwise it signals a special non-error exception to
    the host application (which will normally still lead to aborting
    execution, similar to the standard dereference operator, unless the
    host application specifically handles this exception differently).

.. spicy:operator:: unit::Unset void unset <sp> t:unit.<field>

    Clears an optional field.

