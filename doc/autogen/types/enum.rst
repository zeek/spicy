.. rubric:: Operators

.. spicy:operator:: enum_::Call enum~{~~} t:type<enum~{~~}>(<operand~list>)

    Instantiates an enum instance initialized from an integer value. The
    value does *not* need to correspond to any of the type's enumerator
    labels.

.. spicy:operator:: enum_::Cast enum cast<uint>(type<enum~{~~}>)

    Casts an unsigned integer value to an enum instance. The value does
    *not* need to correspond to any of the type's enumerator labels

.. spicy:operator:: enum_::Cast int cast<enum~{~~}>(type<int>)

    Casts an enum value into a signed integer. If the enum value is
    ``Undef``, this will return ``-1``.

.. spicy:operator:: enum_::Cast uint cast<enum~{~~}>(type<uint>)

    Casts an enum value into a unsigned integer. This will throw an
    exception if the enum value is ``Undef``.

.. spicy:operator:: enum_::Equal bool t:enum~{~~} <sp> op:== <sp> t:enum

    Compares two enum values.

.. spicy:operator:: enum_::Unequal bool t:enum~{~~} <sp> op:!= <sp> t:enum

    Compares two enum values.

