
.. _packing:

==========================
Packing / Unpacking Values
==========================

A few of Spicy's atomic types support low-level conversion from, or
into, a binary representation through two operators:

- ``pack(VALUE, ARGS)`` turns a ``VALUE`` into a sequence of raw bytes
  representing the value in binary form. ``ARGS`` specify what
  encoding to use for the representation; they are type-specific (see
  below for a list).  The ``pack`` operator returns a ``bytes``
  instance containing the encoded data.

  As an example, ``pack(uint16(513), spicy::ByteOrder::Network)``
  returns ``\x02\x01``, which is 513 in network byte order.

- ``unpack<TYPE>(DATA, ARGS)`` parses a value of type ``TYPE`` from a
  binary representation ``DATA``. ``ARGS`` specify what encoding to
  expect for ``DATA``. The ``unpack`` operator returns a 2-tuple
  ``(VALUE, REMAINDER)`` where ``VALUE`` is the parsed value, and
  ``REMAINDER`` is any bytes left over from ``DATA`` that weren't used
  for parsing the value. If parsing fails, ``unpack`` throws an
  ``InvalidValue`` exception.

  As an example, ``unpack<uint16>(b"\x02\x01XYZ",
  spicy::ByteOrder::Network)`` returns the tuple ``(513, b"XYZ")``.

The following table summarizes the types that currently support
packing/unpacking, along with the encoding arguments that the
operators expect for each:

.. list-table::
    :header-rows: 1
    :align: left

    * - Type
      - ``pack``
      - ``unpack``
      - Links

    * - :ref:`type_address`
      - ``pack(VALUE, spicy::ByteOrder)``
      - ``unpack<addr>(DATA, spicy::ByteOrder)``
      - :ref:`Address Family <spicy_addressfamily>`, :ref:`Byte Order <spicy_byteorder>`

    * - :ref:`type_integer`
      - ``pack(VALUE, spicy::ByteOrder)``
      - ``unpack<uintX|intX>(DATA, spicy::ByteOrder)``
      - :ref:`Address Family <spicy_addressfamily>`, :ref:`Byte Order <spicy_byteorder>`

    * - :ref:`type_real`
      - ``pack(VALUE, spicy::RealType, spicy::ByteOrder)``
      - ``unpack<uintX|intX>(DATA, spicy::RealType, spicy::ByteOrder)``
      - :ref:`Real Type <spicy_realtype>` [1], :ref:`Byte Order <spicy_byteorder>`

.. note::

  [1] Packing a ``real`` value as ``IEEE754_Single`` may loose information.
