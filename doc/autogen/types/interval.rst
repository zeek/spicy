.. rubric:: Methods

.. spicy:method:: interval::nanoseconds interval nanoseconds False int<64> ()

    Returns the interval as an integer value representing nanoseconds.

.. spicy:method:: interval::seconds interval seconds False real ()

    Returns the interval as a real value representing seconds.

.. rubric:: Operators

.. spicy:operator:: interval::Call interval interval(int)

    Creates an interval interpreting the argument as number of seconds.

.. spicy:operator:: interval::Call interval interval(real)

    Creates an interval interpreting the argument as number of seconds.

.. spicy:operator:: interval::Call interval interval(uint)

    Creates an interval interpreting the argument as number of seconds.

.. spicy:operator:: interval::Call interval interval_ns(int)

    Creates an interval interpreting the argument as number of
    nanoseconds.

.. spicy:operator:: interval::Call interval interval_ns(uint)

    Creates an interval interpreting the argument as number of
    nanoseconds.

.. spicy:operator:: interval::Difference interval t:interval <sp> op:- <sp> t:interval

    Returns the difference of the intervals.

.. spicy:operator:: interval::Equal bool t:interval <sp> op:== <sp> t:interval

    Compares two interval values.

.. spicy:operator:: interval::Greater bool t:interval <sp> op:> <sp> t:interval

    Compares the intervals.

.. spicy:operator:: interval::GreaterEqual bool t:interval <sp> op:>= <sp> t:interval

    Compares the intervals.

.. spicy:operator:: interval::Lower bool t:interval <sp> op:< <sp> t:interval

    Compares the intervals.

.. spicy:operator:: interval::LowerEqual bool t:interval <sp> op:<= <sp> t:interval

    Compares the intervals.

.. spicy:operator:: interval::Multiple interval t:interval <sp> op:* <sp> t:real $commutative$

    Multiplies the interval with the given factor.

.. spicy:operator:: interval::Multiple interval t:interval <sp> op:* <sp> t:uint<64> $commutative$

    Multiples the interval with the given factor.

.. spicy:operator:: interval::Sum interval t:interval <sp> op:+ <sp> t:interval

    Returns the sum of the intervals.

.. spicy:operator:: interval::Unequal bool t:interval <sp> op:!= <sp> t:interval

    Compares two interval values.

