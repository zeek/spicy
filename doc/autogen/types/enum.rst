.. rubric:: Methods

.. spicy:method:: enum_::has_label enum has_label False bool ()

    Returns *true* if the value of *op1* corresponds to a known enum label
    (other than ``Undef``), as defined by it's type.

.. rubric:: Operators

.. spicy:operator:: enum_::Call enum enum-type(int)

    Instantiates an enum instance initialized from a signed integer value.
    The value does *not* need to correspond to any of the type's
    enumerator labels.

.. spicy:operator:: enum_::Call enum enum-type(uint)

    Instantiates an enum instance initialized from an unsigned integer
    value. The value does *not* need to correspond to any of the type's
    enumerator labels. It must not be larger than the maximum that a
    *signed* 64-bit integer value can represent.

.. spicy:operator:: enum_::Cast int cast<int-type>(enum)

    Casts an enum value into a signed integer. If the enum value is
    ``Undef``, this will return ``-1``.

.. spicy:operator:: enum_::Cast uint cast<uint-type>(enum)

    Casts an enum value into a unsigned integer. This will throw an
    exception if the enum value is ``Undef``.

.. spicy:operator:: enum_::Equal bool t:enum <sp> op:== <sp> t:enum

    Compares two enum values.

.. spicy:operator:: enum_::Unequal bool t:enum <sp> op:!= <sp> t:enum

    Compares two enum values.

