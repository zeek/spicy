.. rubric:: Operators

.. spicy:operator:: integer::BitAnd uint t:uint <sp> op:& <sp> t:uint

    Computes the bit-wise 'and' of the two integers.

.. spicy:operator:: integer::BitOr uint t:uint <sp> op:| <sp> t:uint

    Computes the bit-wise 'or' of the two integers.

.. spicy:operator:: integer::BitXor uint t:uint <sp> op:^ <sp> t:uint

    Computes the bit-wise 'xor' of the two integers.

.. spicy:operator:: integer::Cast int cast<int>(type<int>)

    Converts the value to another signed integer type, accepting any loss
    of information.

.. spicy:operator:: integer::Cast int cast<uint>(type<int>)

    Converts the value to signed integer type, accepting any loss of
    information.

.. spicy:operator:: integer::Cast real cast<int>(type<real>)

    Converts the value into a real, accepting any loss of information.

.. spicy:operator:: integer::Cast real cast<uint>(type<real>)

    Converts the value into a real, accepting any loss of information.

.. spicy:operator:: integer::Cast uint cast<int>(type<uint>)

    Converts the value to an unsigned integer type, accepting any loss of
    information.

.. spicy:operator:: integer::Cast uint cast<uint>(type<uint>)

    Converts the value to another unsigned integer type, accepting any
    loss of information.

.. spicy:operator:: integer::DecrPostfix int op: t:int op:--

    Decrements the value, returning the old value.

.. spicy:operator:: integer::DecrPostfix uint op: t:uint op:--

    Decrements the value, returning the old value.

.. spicy:operator:: integer::DecrPrefix int op:++ t:int op:

    Increments the value, returning the new value.

.. spicy:operator:: integer::DecrPrefix uint op:++ t:uint op:

    Increments the value, returning the new value.

.. spicy:operator:: integer::Difference uint t:uint <sp> op:- <sp> t:uint

    Computes the difference between the two integers.

.. spicy:operator:: integer::Difference uint t:uint <sp> op:- <sp> t:uint

    Returns the difference between the two integers.

.. spicy:operator:: integer::DifferenceAssign int t:int <sp> op:+= <sp> t:int

    Decrements the first value by the second, assigning the new value.

.. spicy:operator:: integer::DifferenceAssign uint t:uint <sp> op:+= <sp> t:uint

    Decrements the first value by the second.

.. spicy:operator:: integer::Division uint t:uint <sp> op:/ <sp> t:uint

    Divides the first integer by the second.

.. spicy:operator:: integer::DivisionAssign int t:int <sp> op:+/ <sp> t:int

    Divides the first value by the second, assigning the new value.

.. spicy:operator:: integer::DivisionAssign uint t:uint <sp> op:+/ <sp> t:uint

    Divides the first value by the second, assigning the new value.

.. spicy:operator:: integer::Equal bool t:uint <sp> op:== <sp> t:uint

    Compares the two integers.

.. spicy:operator:: integer::Greater bool t:uint <sp> op:> <sp> t:uint

    Compares the two integers.

.. spicy:operator:: integer::GreaterEqual bool t:uint <sp> op:>= <sp> t:uint

    Compares the two integers.

.. spicy:operator:: integer::IncrPostfix int op: t:int op:++

    Increments the value, returning the old value.

.. spicy:operator:: integer::IncrPostfix uint op: t:uint op:++

    Increments the value, returning the old value.

.. spicy:operator:: integer::IncrPrefix int op:++ t:int op:

    Increments the value, returning the new value.

.. spicy:operator:: integer::IncrPrefix uint op:++ t:uint op:

    Increments the value, returning the new value.

.. spicy:operator:: integer::Lower bool t:uint <sp> op:< <sp> t:uint

    Compares the two integers.

.. spicy:operator:: integer::LowerEqual bool t:uint <sp> op:<= <sp> t:uint

    Compares the two integers.

.. spicy:operator:: integer::Modulo uint t:uint <sp> op:% <sp> t:uint

    Computes the modulus of the first integer divided by the second.

.. spicy:operator:: integer::Multiple uint t:uint <sp> op:* <sp> t:uint

    Multiplies the first integer by the second.

.. spicy:operator:: integer::MultipleAssign int t:int <sp> op:*= <sp> t:int

    Multiplies the first value by the second, assigning the new value.

.. spicy:operator:: integer::MultipleAssign uint t:uint <sp> op:*= <sp> t:uint

    Multiplies the first value by the second, assigning the new value.

.. spicy:operator:: integer::Negate uint op:~ t:uint op:

    Computes the bit-wise negation of the integer.

.. spicy:operator:: integer::Power uint t:uint <sp> op:** <sp> t:uint

    Computes the first integer raised to the power of the second.

.. spicy:operator:: integer::ShiftLeft uint t:uint <sp> op:<< <sp> t:uint

    Shifts the integer to the left by the given number of bits.

.. spicy:operator:: integer::ShiftRight uint t:uint <sp> op:>> <sp> t:uint

    Shifts the integer to the right by the given number of bits.

.. spicy:operator:: integer::SignNeg int op:- t:int op:

    Inverts the sign of the integer.

.. spicy:operator:: integer::Sum uint t:uint <sp> op:+ <sp> t:uint

    Computes the sum of the integers.

.. spicy:operator:: integer::Sum uint t:uint <sp> op:+ <sp> t:uint

    Returns the sum of the integers.

.. spicy:operator:: integer::SumAssign int t:int <sp> op:+= <sp> t:int

    Increments the first integer by the second, assigning the new value.

.. spicy:operator:: integer::SumAssign uint t:uint <sp> op:+= <sp> t:uint

    Increments the first value by the second.

.. spicy:operator:: integer::Unequal bool t:uint <sp> op:!= <sp> t:uint

    Compares the two integers.

