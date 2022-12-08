.. rubric:: Methods

.. spicy:method:: time::nanoseconds time nanoseconds False uint<64> ()

    Returns the time as an integer value representing nanoseconds since
    the UNIX epoch.

.. spicy:method:: time::seconds time seconds False real ()

    Returns the time as a real value representing seconds since the UNIX
    epoch.

.. rubric:: Operators

.. spicy:operator:: time::Call time time(int)

    Creates an time interpreting the argument as number of seconds.

.. spicy:operator:: time::Call time time(real)

    Creates an time interpreting the argument as number of seconds.

.. spicy:operator:: time::Call time time(uint)

    Creates an time interpreting the argument as number of seconds.

.. spicy:operator:: time::Call time time_ns(int)

    Creates an time interpreting the argument as number of nanoseconds.

.. spicy:operator:: time::Call time time_ns(uint)

    Creates an time interpreting the argument as number of nanoseconds.

.. spicy:operator:: time::Difference interval t:time <sp> op:- <sp> t:time

    Returns the difference of the times.

.. spicy:operator:: time::Difference time t:time <sp> op:- <sp> t:interval

    Subtracts the interval from the time.

.. spicy:operator:: time::Equal bool t:time <sp> op:== <sp> t:time

    Compares two time values.

.. spicy:operator:: time::Greater bool t:time <sp> op:> <sp> t:time

    Compares the times.

.. spicy:operator:: time::GreaterEqual bool t:time <sp> op:>= <sp> t:time

    Compares the times.

.. spicy:operator:: time::Lower bool t:time <sp> op:< <sp> t:time

    Compares the times.

.. spicy:operator:: time::LowerEqual bool t:time <sp> op:<= <sp> t:time

    Compares the times.

.. spicy:operator:: time::Sum time t:time <sp> op:+ <sp> t:interval $commutative$

    Adds the interval to the time.

.. spicy:operator:: time::Unequal bool t:time <sp> op:!= <sp> t:time

    Compares two time values.

