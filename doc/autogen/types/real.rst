.. rubric:: Operators

.. spicy:operator:: real::Cast int cast<int-type>(real)

    Converts the value to a signed integer type, accepting any loss of
    information.

.. spicy:operator:: real::Cast interval cast<interval-type>(real)

    Interprets the value as number of seconds.

.. spicy:operator:: real::Cast time cast<time-type>(real)

    Interprets the value as number of seconds since the UNIX epoch.

.. spicy:operator:: real::Cast uint cast<uint-type>(real)

    Converts the value to an unsigned integer type, accepting any loss of
    information.

.. spicy:operator:: real::Difference real t:real <sp> op:- <sp> t:real

    Returns the difference between the two values.

.. spicy:operator:: real::DifferenceAssign real t:real <sp> op:-= <sp> t:real

    Subtracts the second value from the first, assigning the new value.

.. spicy:operator:: real::Division real t:real <sp> op:/ <sp> t:real

    Divides the first value by the second.

.. spicy:operator:: real::DivisionAssign real t:real <sp> op:/= <sp> t:real

    Divides the first value by the second, assigning the new value.

.. spicy:operator:: real::Equal bool t:real <sp> op:== <sp> t:real

    Compares the two reals.

.. spicy:operator:: real::Greater bool t:real <sp> op:> <sp> t:real

    Compares the two reals.

.. spicy:operator:: real::GreaterEqual bool t:real <sp> op:>= <sp> t:real

    Compares the two reals.

.. spicy:operator:: real::Lower bool t:real <sp> op:< <sp> t:real

    Compares the two reals.

.. spicy:operator:: real::LowerEqual bool t:real <sp> op:<= <sp> t:real

    Compares the two reals.

.. spicy:operator:: real::Modulo real t:real <sp> op:% <sp> t:real

    Computes the modulus of the first real divided by the second.

.. spicy:operator:: real::Multiple real t:real <sp> op:* <sp> t:real

    Multiplies the first real by the second.

.. spicy:operator:: real::MultipleAssign real t:real <sp> op:*= <sp> t:real

    Multiplies the first value by the second, assigning the new value.

.. spicy:operator:: real::Power real t:real <sp> op:** <sp> t:real

    Computes the first real raised to the power of the second.

.. spicy:operator:: real::SignNeg real op:- t:real op:

    Inverts the sign of the real.

.. spicy:operator:: real::Sum real t:real <sp> op:+ <sp> t:real

    Returns the sum of the reals.

.. spicy:operator:: real::SumAssign real t:real <sp> op:+= <sp> t:real

    Adds the first real to the second, assigning the new value.

.. spicy:operator:: real::Unequal bool t:real <sp> op:!= <sp> t:real

    Compares the two reals.

