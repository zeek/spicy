.. rubric:: Operators

.. spicy:operator:: integer::BitAnd uint t:uint <sp> op:& <sp> t:uint

    Computes the bit-wise 'and' of the two integers.

.. spicy:operator:: integer::BitOr uint t:uint <sp> op:| <sp> t:uint

    Computes the bit-wise 'or' of the two integers.

.. spicy:operator:: integer::BitXor uint t:uint <sp> op:^ <sp> t:uint

    Computes the bit-wise 'xor' of the two integers.

.. spicy:operator:: integer::Call int<16> int16(int)

    Creates a 16-bit signed integer value.

.. spicy:operator:: integer::Call int<16> int16(uint)

    Creates a 16-bit signed integer value.

.. spicy:operator:: integer::Call int<32> int32(int)

    Creates a 32-bit signed integer value.

.. spicy:operator:: integer::Call int<32> int32(uint)

    Creates a 32-bit signed integer value.

.. spicy:operator:: integer::Call int<64> int64(int)

    Creates a 64-bit signed integer value.

.. spicy:operator:: integer::Call int<64> int64(uint)

    Creates a 64-bit signed integer value.

.. spicy:operator:: integer::Call int<8> int8(int)

    Creates a 8-bit signed integer value.

.. spicy:operator:: integer::Call int<8> int8(uint)

    Creates a 8-bit signed integer value.

.. spicy:operator:: integer::Call uint<16> uint16(int)

    Creates a 16-bit unsigned integer value.

.. spicy:operator:: integer::Call uint<16> uint16(uint)

    Creates a 16-bit unsigned integer value.

.. spicy:operator:: integer::Call uint<32> uint32(int)

    Creates a 32-bit unsigned integer value.

.. spicy:operator:: integer::Call uint<32> uint32(uint)

    Creates a 32-bit unsigned integer value.

.. spicy:operator:: integer::Call uint<64> uint64(int)

    Creates a 64-bit unsigned integer value.

.. spicy:operator:: integer::Call uint<64> uint64(uint)

    Creates a 64-bit unsigned integer value.

.. spicy:operator:: integer::Call uint<8> uint8(int)

    Creates a 8-bit unsigned integer value.

.. spicy:operator:: integer::Call uint<8> uint8(uint)

    Creates a 8-bit unsigned integer value.

.. spicy:operator:: integer::Cast bool cast<bool-type>(int)

    Converts the value to a boolean by comparing against zero

.. spicy:operator:: integer::Cast enum cast<enum-type>(int)

    Converts the value into an enum instance. The value does *not* need to
    correspond to any of the target type's enumerator labels.

.. spicy:operator:: integer::Cast enum cast<enum-type>(uint)

    Converts the value into an enum instance. The value does *not* need to
    correspond to any of the target type's enumerator labels. It must not
    be larger than the maximum that a *signed* 64-bit integer value can
    represent.

.. spicy:operator:: integer::Cast int cast<int-type>(int)

    Converts the value into another signed integer type, accepting any
    loss of information.

.. spicy:operator:: integer::Cast int cast<int-type>(uint)

    Converts the value into a signed integer type, accepting any loss of
    information.

.. spicy:operator:: integer::Cast interval cast<interval-type>(int)

    Interprets the value as number of seconds.

.. spicy:operator:: integer::Cast interval cast<interval-type>(uint)

    Interprets the value as number of seconds.

.. spicy:operator:: integer::Cast real cast<real-type>(int)

    Converts the value into a real, accepting any loss of information.

.. spicy:operator:: integer::Cast real cast<real-type>(uint)

    Converts the value into a real, accepting any loss of information.

.. spicy:operator:: integer::Cast time cast<time-type>(uint)

    Interprets the value as number of seconds since the UNIX epoch.

.. spicy:operator:: integer::Cast uint cast<uint-type>(int)

    Converts the value into an unsigned integer type, accepting any loss
    of information.

.. spicy:operator:: integer::Cast uint cast<uint-type>(uint)

    Converts the value into another unsigned integer type, accepting any
    loss of information.

.. spicy:operator:: integer::DecrPostfix int op: t:int op:--

    Decrements the value, returning the old value.

.. spicy:operator:: integer::DecrPostfix uint op: t:uint op:--

    Decrements the value, returning the old value.

.. spicy:operator:: integer::DecrPrefix int op:++ t:int op:

    Increments the value, returning the new value.

.. spicy:operator:: integer::DecrPrefix uint op:++ t:uint op:

    Increments the value, returning the new value.

.. spicy:operator:: integer::Difference int t:int <sp> op:- <sp> t:int

    Computes the difference between the two integers.

.. spicy:operator:: integer::Difference uint t:uint <sp> op:- <sp> t:uint

    Computes the difference between the two integers.

.. spicy:operator:: integer::DifferenceAssign int t:int <sp> op:-= <sp> t:int

    Decrements the first value by the second, assigning the new value.

.. spicy:operator:: integer::DifferenceAssign uint t:uint <sp> op:-= <sp> t:uint

    Decrements the first value by the second.

.. spicy:operator:: integer::Division int t:int <sp> op:/ <sp> t:int

    Divides the first integer by the second.

.. spicy:operator:: integer::Division uint t:uint <sp> op:/ <sp> t:uint

    Divides the first integer by the second.

.. spicy:operator:: integer::DivisionAssign int t:int <sp> op:/= <sp> t:int

    Divides the first value by the second, assigning the new value.

.. spicy:operator:: integer::DivisionAssign uint t:uint <sp> op:/= <sp> t:uint

    Divides the first value by the second, assigning the new value.

.. spicy:operator:: integer::Equal bool t:int <sp> op:== <sp> t:int

    Compares the two integers.

.. spicy:operator:: integer::Equal bool t:uint <sp> op:== <sp> t:uint

    Compares the two integers.

.. spicy:operator:: integer::Greater bool t:int <sp> op:> <sp> t:int

    Compares the two integers.

.. spicy:operator:: integer::Greater bool t:uint <sp> op:> <sp> t:uint

    Compares the two integers.

.. spicy:operator:: integer::GreaterEqual bool t:int <sp> op:>= <sp> t:int

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

.. spicy:operator:: integer::Lower bool t:int <sp> op:< <sp> t:int

    Compares the two integers.

.. spicy:operator:: integer::Lower bool t:uint <sp> op:< <sp> t:uint

    Compares the two integers.

.. spicy:operator:: integer::LowerEqual bool t:int <sp> op:<= <sp> t:int

    Compares the two integers.

.. spicy:operator:: integer::LowerEqual bool t:uint <sp> op:<= <sp> t:uint

    Compares the two integers.

.. spicy:operator:: integer::Modulo int t:int <sp> op:% <sp> t:int

    Computes the modulus of the first integer divided by the second.

.. spicy:operator:: integer::Modulo uint t:uint <sp> op:% <sp> t:uint

    Computes the modulus of the first integer divided by the second.

.. spicy:operator:: integer::Multiple int t:int <sp> op:* <sp> t:int

    Multiplies the first integer by the second.

.. spicy:operator:: integer::Multiple uint t:uint <sp> op:* <sp> t:uint

    Multiplies the first integer by the second.

.. spicy:operator:: integer::MultipleAssign int t:int <sp> op:*= <sp> t:int

    Multiplies the first value by the second, assigning the new value.

.. spicy:operator:: integer::MultipleAssign uint t:uint <sp> op:*= <sp> t:uint

    Multiplies the first value by the second, assigning the new value.

.. spicy:operator:: integer::Negate uint op:~ t:uint op:

    Computes the bit-wise negation of the integer.

.. spicy:operator:: integer::Power int t:int <sp> op:** <sp> t:int

    Computes the first integer raised to the power of the second.

.. spicy:operator:: integer::Power uint t:uint <sp> op:** <sp> t:uint

    Computes the first integer raised to the power of the second.

.. spicy:operator:: integer::ShiftLeft uint t:uint <sp> op:<< <sp> t:uint

    Shifts the integer to the left by the given number of bits.

.. spicy:operator:: integer::ShiftRight uint t:uint <sp> op:>> <sp> t:uint

    Shifts the integer to the right by the given number of bits.

.. spicy:operator:: integer::SignNeg int op:- t:int op:

    Inverts the sign of the integer.

.. spicy:operator:: integer::SignNeg int op:- t:uint op:

    Inverts the sign of the integer.

.. spicy:operator:: integer::Sum int t:int <sp> op:+ <sp> t:int

    Computes the sum of the integers.

.. spicy:operator:: integer::Sum uint t:uint <sp> op:+ <sp> t:uint

    Computes the sum of the integers.

.. spicy:operator:: integer::SumAssign int t:int <sp> op:+= <sp> t:int

    Increments the first integer by the second.

.. spicy:operator:: integer::SumAssign uint t:uint <sp> op:+= <sp> t:uint

    Increments the first integer by the second.

.. spicy:operator:: integer::Unequal bool t:int <sp> op:!= <sp> t:int

    Compares the two integers.

.. spicy:operator:: integer::Unequal bool t:uint <sp> op:!= <sp> t:uint

    Compares the two integers.

