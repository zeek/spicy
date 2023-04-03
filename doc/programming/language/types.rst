
.. _types:

=====
Types
=====

.. _type_address:

Address
-------

The address type stores both IPv4 and IPv6 addresses.

.. rubric:: Type

- ``addr``

.. rubric:: Constants

- IPv4: ``1.2.3.4``
- IPv6: ``[2001:db8:85a3:8d3:1319:8a2e:370:7348]``, ``[::1.2.3.4]``

This type supports the :ref:`pack/unpack operators <packing>`.

.. include:: /autogen/types/address.rst

.. _type_bitfield:

Bitfield
--------

Bitfields provide access to individual bitranges inside an unsigned
integer. That can't be instantiated directly, but must be defined and
parsed inside a unit.

.. rubric:: Type

- ``bitfield(N) { RANGE_1; ...; RANGE_N }``
- Each ``RANGE`` has one of the forms ``LABEL: A`` or ``LABEL: A..B``
  where ``A`` and ``B`` are bit numbers.

.. include:: /autogen/types/bitfield.rst

.. _type_bool:

Bool
----

Boolean values can be ``True`` or ``False``.

.. rubric:: Type

- ``bool``

.. rubric:: Constants

- ``True``, ``False``

.. include:: /autogen/types/bool.rst

.. _type_bytes:

Bytes
-----

Bytes instances store raw, opaque data. They provide iterators to
traverse their content.

.. rubric:: Types

- ``bytes``
- ``iterator<bytes>``

.. rubric:: Constants

- ``b"Spicy"``, ``b""``

.. include:: /autogen/types/bytes.rst
.. include:: /autogen/types/bytes-iterator.rst

.. _type_enum:

Enum
----

Enum types associate labels with numerical values.

.. rubric:: Type

- ``enum { LABEL_1, ..., LABEL_N }``
- Each label has the form ``ID [= VALUE]``. If ``VALUE`` is skipped,
  one will be assigned automatically.

- Each enum type comes with an implicitly defined ``Undef`` label with
  a value distinct from all other ones. When coerced into a boolean,
  an enum will be true iff it's not ``Undef``.

.. note:: An instance of an enum can assume a numerical value that
   does not map to any of its defined labels. If printed, it will then
   render into ``<unknown-N>`` in that case, with ``N`` being the
   decimal expression of its numeric value.

.. rubric:: Constants

- The individual labels represent constants of the corresponding type
  (e.g., ``MyEnum::MyFirstLabel`` is a constant of type ``MyEnum``).

.. include:: /autogen/types/enum.rst

.. _type_exception:

Exception
---------

.. todo:: This isn't available in Spicy yet (:issue:`89`).

.. _type_integer:

Integer
-------

Spicy distinguishes between signed and unsigned integers, and always
requires specifying the bitwidth of a type.

.. rubric:: Type

- ``intN`` for signed integers, where ``N`` can be one of 8, 16, 32, 64.
- ``uintN`` for unsigned integers, where ``N`` can be one of 8, 16, 32, 64.

.. rubric:: Constants

- Unsigned integer: ``1234``, ``+1234``, ``uint8(42)``, ``uint16(42)``, ``uint32(42)``, ``uint64(42)``
- Signed integer: ``-1234``, ``int8(42)``, ``int8(-42)``, ``int16(42)``, ``int32(42)``, ``int64(42)``

This type supports the :ref:`pack/unpack operators <packing>`.

.. include:: /autogen/types/integer.rst

Interval
--------

Am interval value represents a period of time. Intervals are stored
with nanosecond resolution, which is retained across all calculations.

.. rubric:: Type

- ``interval``

.. rubric:: Constants

- ``interval(SECS)`` creates an interval from a signed integer or real
  value ``SECS`` specifying the period in seconds.

- ``interval_ns(NSECS)`` creates an interval from a signed integer
  value ``NSECS`` specifying the period in nanoseconds.

.. include:: /autogen/types/time.rst

.. _type_list:

List
----

Spicy uses lists only in a limited form as temporary values, usually
for initializing other containers. That means you can only create list
constants, but you cannot declare variables or unit fields to have a
``list`` type (use :ref:`vector <type_vector>` instead).

.. rubric:: Constants

- ``[E_1, E_2, ..., E_N]`` creates a list of ``N`` elements. The
  values ``E_I`` must all have the same type. ``[]`` creates an empty
  list of unknown element type.

- ``[EXPR for ID in ITERABLE]`` creates a list by evaluating ``EXPR``
  for all elements in ``ITERABLE``, assembling the individual results
  into the final list value. The extended form ``[EXPR for ID in
  SEQUENCE if COND]`` includes only elements into the result for which
  ``COND`` evaluates to ``True``. Both ``EXPR`` and ``COND`` can use
  ``ID`` to refer to the current element.

- ``list(E_1, E_2, ..., E_N)`` is the same as ``[E_1, E_2, ...,
  E_N]``, and ``list()`` is the same as ``[]``.

- ``list<T>(E_1, E_2, ..., E_N)`` creates a list of type ``T``,
  initializing it with the ``N`` elements ``E_I``. ``list<T>()``
  creates an empty list.

.. include:: /autogen/types/list.rst

Map
---

Maps are containers holding key/value pairs of elements, with fast
lookup for keys to retrieve the corresponding value. They provide
iterators to traverse their content, with no particular ordering.

.. rubric:: Types

- ``map<K, V>`` specifies a map with key type ``K`` and value type ``V``.
- ``iterator<map<K, V>>``

.. rubric:: Constants

- ``map(K_1: V_1, K_2: V_2, ..., K_N: V_N)`` creates a map of ``N``
  elements, initializing it with the given key/value pairs. The keys
  ``K_I`` must all have the same type, and the values ``V_I`` must
  likewise all have the same type. ``map()`` creates an empty map of
  unknown key/value types; this cannot be used directly but must be
  coerced into a fully-defined map type first.

- ``map<K, V>(K_1: V_1, K_2: V_2, ..., K_N: V_N)`` creates a map of
  type ``map<K, V>``, initializing it with the given key/value pairs.
  ``map<K, V>()`` creates an empty map.

.. include:: /autogen/types/map.rst
.. include:: /autogen/types/map-iterator.rst

.. _type_optional:

Optional
--------

An ``optional`` value may hold a value of another type, or can alternatively
remain unset. A common use case for ``optional`` is the return value of a
function that may fail.

- ``optional<TYPE>``

.. rubric:: Constants

- ``optional(EXPR)`` creates an ``optional<T>``, where ``T`` is the
  type of the expression ``EXPR`` and initializes it with the value of
  ``EXPR``.

More commonly, however, ``optional`` values are initialized through assignment:

- Assigning an instance of ``TYPE`` to an ``optional<TYPE>`` sets it
  to the instance's value.

- Assigning ``Null`` to an ``optional<TYPE>`` unsets it.

To check whether an ``optional`` value is set, it can implicitly or explicitly
be converted to a ``bool``.

.. spicy-code:: optional-check.spicy

    global x: optional<uint64>;  # Unset.
    global b1: bool = x;         # False.
    global b2 = cast<bool>(x);   # False.

    if ( x )
        print "'x' was set";     # Never runs.
    if ( ! x )
        print "'x' was unset";   # Always runs.

.. include:: /autogen/types/optional.rst

.. _type_port:

Port
----

Ports represent the combination of a numerical port number and an
associated transport-layer protocol.

.. rubric:: Type

- ``port``

.. rubric:: Constants

- ``443/tcp``, ``53/udp``

- ``port(PORT, PROTOCOL)`` creates a ``port`` where ``PORT`` is a port number and ``PROTOCOL`` a :ref:`spicy::Protocol <spicy_protocol>`.

.. include:: /autogen/types/port.rst

.. _type_real:

Real
----

"Real" values store floating points with double precision.

.. rubric:: Type

- ``real``

.. rubric:: Constants

- ``3.14``, ``10e9``, ``0x1.921fb78121fb8p+1``

This type supports the :ref:`pack/unpack operators <packing>`.

.. include:: /autogen/types/real.rst

.. _type_regexp:

Regular Expression
------------------

Spicy provides POSIX-style regular expressions.

.. rubric:: Type

- ``regexp``

.. rubric:: Constants

- ``/Foo*bar?/``, ``/X(..)(..)(..)Y/``

Regular expressions use the extended POSIX syntax, with a few smaller
differences and extensions:

- Supported character classes are: ``[:lower:]``, ``[:upper:]``,
  ``[:digit:]``, ``[:blank:]``.
- ``\b`` asserts a word-boundary, ``\B`` matches asserts no word
  boundary.
- ``\xXX`` matches a byte with the binary hex value ``XX`` (e.g.,
  ``\xff`` matches a byte of decimal value 255).
- ``{#<number>}`` associates a numerical ID with a regular expression
  (useful for set matching).

Regular expression constants support two optional attributes:

``&anchor``
    Implicitly anchor the expression, meaning it must match at the
    beginning of the data.

``&nosub``
    Compile without support for capturing subexpressions, which makes
    matching more efficient.


.. include:: /autogen/types/regexp.rst

.. _type_set:

Set
---

Sets are containers for unique elements with fast lookup. They provide
iterators to traverse their content, with no particular ordering.

.. rubric:: Types

- ``set<T>`` specifies a set with unique elements of type ``T``.
- ``iterator<set<T>>``

.. rubric:: Constants

- ``set(E_1, E_2, ..., E_N)`` creates a set of ``N`` elements.
  The values ``E_I`` must all have the same type. ``set()`` creates
  an empty set of unknown element type; this cannot be used
  directly but must be coerced into a fully-defined set type first.

- ``set<T>(E_1, E_2, ..., E_N)`` creates a set of type ``T``,
  initializing it with the elements ``E_I``. ``set<T>()`` creates
  an empty set.

.. include:: /autogen/types/set.rst
.. include:: /autogen/types/set-iterator.rst

.. _type_sink:

Sink
----

Sinks act as a connector between two units, facilitating feeding the
output of one as input into the other. See :ref:`sinks` for a full
description.

Sinks are special in that they don't represent a type that's generally
available for instantiation. Instead they need to be declared as the
member of unit using the special ``sink`` keyword. You can, however,
maintain references to sinks by assigning the unit member to a variable
of type ``Sink&``.

.. include:: /autogen/types/sink.rst

.. rubric: Hooks

Sinks provide a set of dedicated unit hooks as callbacks for the
reassembly process. These must be implemented on the reader side,
i.e., the unit that's connected to a sink.

.. spicy:method:: %on_gap sink %on_gap False - (seq: uint64, len: uint64)

.. spicy:method:: %on_overlap sink %on_overlap False - (seq: uint64, old: data, new: data)

Triggered when reassembly encounters a 2nd version of data for
sequence space already covered earlier. *seq* is the start of the
overlap, and *old*/*new* the previous and the new data, respectively.
This hook is just for informational purposes, the policy set with
:spicy:method:`sink::set_policy` determines how the reassembler
handles the overlap.

.. spicy:method:: %on_skipped sink %on_skipped False - (seq: uint64)

Any time :spicy:method:`sink::skip`   moves ahead in the input stream, this hook reports
the new sequence number *seq*.

.. spicy:method:: %on_undelivered sink %on_skipped False - (seq: uint64, data: bytes)

If data still buffered is skipped over through
:spicy:method:`sink::skip`, it will be passed to this hook, before
adjusting the current position. *seq* is the starting sequence number
of the data, *data* is the data itself.

.. _type_stream:

Stream
------

A ``stream`` is data structure that efficiently represents a
potentially large, incrementally provided input stream of raw data.
You can think of it as a :ref:`bytes <type_bytes>` type that's
optimized for (1) efficiently appending new chunks of data at the end,
and (2) trimming data no longer needed at the beginning. Other than
those two operation, stream data cannot be modified; there's no way to
change the actual content of a stream once it has been added to it.
Streams provide *iterators* for traversal, and *views* for limiting
visibility to smaller windows into the total stream.

Streams are key to Spicy's parsing process, although most of that
happens behind the scenes. You will most likely encounter them when
using :ref:`random_access`. They may also be useful for buffering
larger volumes of data during processing.

.. rubric:: Types

- ``stream``
- ``iterator<stream>``
- ``view<stream>``

.. include:: /autogen/types/stream.rst
.. include:: /autogen/types/stream-iterator.rst
.. include:: /autogen/types/stream-view.rst

.. _type_string:

String
------

Strings store readable text that's associated with a given character
set. Internally, Spicy stores them as UTF-8.

.. rubric:: Type

- ``string``

.. rubric:: Constants

- ``"Spicy"``, ``""``
- When specifying string constants, Spicy assumes them to be in UTF-8.

.. include:: /autogen/types/string.rst

.. _type_struct:

Struct
------

A struct is a heterogeneous container of an ordered set of named values similar
to a :ref:`type_tuple`. In contrast to ``tuple`` elements, ``struct`` fields
are mutable.

.. rubric:: Type

- ``struct { IDENTIFIER_1: TYPE_1; ...; IDENTIFIER_N: TYPE_N;  }``

.. rubric:: Constants

.. _struct_initializer:

- Structs can be initialized with a ``struct`` initializer,
  ``local my_struct: MyStruct = [$FIELD_1 = X_1, ..., $FIELD_N = X_N]`` where
  ``FIELD_I`` is the label of the corresponding field in ``MyStruct``'s type.

.. include:: /autogen/types/struct.rst

.. _type_time:

Time
----

A time value refers to a specific, absolute point of time, specified
as the interval from January 1, 1970 UT ( i.e., the Unix epoch). Times
are stored with nanosecond resolution, which is retained across all
calculations.

.. rubric:: Type

- ``time``

.. rubric:: Constants

- ``time(SECS)`` creates a time from an unsigned integer or real value
  ``SECS`` specifying seconds since the epoch.

- ``time_ns(NSECS)`` creates a time from an unsigned integer value
  ``NSECS`` specifying nanoseconds since the epoch.

.. include:: /autogen/types/time.rst

.. _type_tuple:

Tuple
-----

Tuples are heterogeneous containers of a fixed, ordered set of types.
Tuple elements may optionally be declared and addressed with custom
identifier names. Tuple elements are immutable.

.. rubric:: Type

- ``tuple<[IDENTIFIER_1: ]TYPE_1, ...[IDENTIFIER_N: ]TYPE_N>``

.. rubric:: Constants

- ``(1, "string", True)``, ``(1, )``, ``()``
- ``tuple(1, "string", True)``, ``tuple(1)``, ``tuple()``

.. include:: /autogen/types/tuple.rst

.. _type_unit:

Unit
----

.. rubric:: Type

- ``unit { FIELD_1; ...; FIELD_N }``

- See :ref:`parsing` for a full discussion of unit types.

.. rubric:: Constants

- Spicy doesn't support unit constants, but you can initialize unit
  instances through coercion from a ``struct`` initializer, see
  :ref:`type_struct`.

  .. todo:: This initialization isn't actually available in Spicy yet (:issue:`1036`).

.. include:: /autogen/types/unit.rst

.. _type_vector:

Vector
------

Vectors are homogeneous containers, holding a set of elements of a
given element type. They provide iterators to traverse their content.

.. rubric:: Types

- ``vector<T>`` specifies a vector with elements of type ``T``.
- ``iterator<vector<T>>``

.. rubric:: Constants

- ``vector(E_1, E_2, ..., E_N)`` creates a vector of ``N`` elements.
  The values ``E_I`` must all have the same type. ``vector()`` creates
  an empty vector of unknown element type; this cannot be used
  directly but must be coerced into a fully-defined vector type first.

- ``vector<T>(E_1, E_2, ..., E_N)`` creates a vector of type ``T``,
  initializing it with the ``N`` elements ``E_I``. ``vector<T>()`` creates
  an empty vector.

- Vectors can be initialized through coercion from a list value:
  ``vector<string> I = ["A", "B", "C"]``.

.. include:: /autogen/types/vector.rst
.. include:: /autogen/types/vector-iterator.rst

.. _type_void:

Void
----

The void type is place holder for specifying "no type", such as when a
function doesn't return anything.

.. rubric:: Type

- ``void``
