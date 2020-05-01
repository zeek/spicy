
.. _parsing:

=======
Parsing
=======

Basics
======

.. rubric:: Type Declaration

Spicy expresses units of data to parse through a type called,
appropriately, ``unit``. At a high level, a unit is similar to structs
or records in other languages: It defines an ordered set of fields,
each with a name and a type, that during runtime will store
corresponding values. Units can be instantiated, fields can be
assigned values, and these values can then be retrieved. Here's about
the most basic Spicy unit one can define::

    type Foo = unit {
        version: uint32;
    };

We name the type ``Foo``, and it has just one field called
``version``, which stores a 32-bit unsigned integer type.

Leaving parsing aside for a moment, we can indeed use this type
similar to a typical struct/record type:

.. spicy-code:: basic-unit-module.spicy

    module Test;

    type Foo = unit {
        version: uint32;
    };

    global f: Foo;
    f.version = 42;
    print f;

This will print:

.. spicy-output:: basic-unit-module.spicy
    :exec: spicyc -j %INPUT

Fields are initially unset, and attempting to read an unset field will
trigger a :ref:`runtime exception <exceptions>`. You may, however,
provide a default value by adding a `&default` *attribute* to the
field, in which case that will be returned on access if no value has
been explicitly assigned:

.. spicy-code:: basic-unit-module-with-default.spicy

    module Test;

    type Foo = unit {
        version: uint32 &default=42;
    };

    global f: Foo;
    print f;
    print "version is %s" % f.version;

This will print:

.. spicy-output:: basic-unit-module-with-default.spicy
    :exec: spicyc -j %INPUT

Note how the field remains unset even with the default now specified,
while the access returns the expected value.

.. rubric:: Parsing a Field

We can turn this minimal unit type into a starting point for parsing
data---in this case a 32-bit integer from four bytes of raw input.
First, we need to declare the unit as ``public`` to make it accessible
from outside of the current module---a requirement if a host
application wants to use the unit as a parsing entry point.

.. spicy-code:: basic-unit-parse.spicy

    module Test;

    public type Foo = unit {
        version: uint32;

        on %done {
            print "0x%x" % self.version;
        }
    };

Let's use :ref:`spicy-driver` to parse 4 bytes of input through this
unit:

.. spicy-output:: basic-unit-parse.spicy
    :exec: printf '\01\02\03\04' | spicy-driver %INPUT
    :show-with: foo.spicy

The output comes of course from the ``print`` statement inside the
``%done`` hook, which executes once the unit has been fully parsed.
(We will discuss unit hooks further below.)

By default, Spicy assumes integers that it parses to be represented in
network byte order (i.e., big-endian), hence the output above.
Alternatively, we can tell the parser through an attribute that our
input is arriving in, say, little-endian instead. To do that, we
import the ``spicy`` library module, which provides an enum type
:ref:`spicy_byteorder` that we can give to a ``&byte-order`` field
attribute that integer fields support:

.. spicy-code:: basic-unit-parse-byte-order.spicy

    module Test;

    import spicy;

    public type Foo = unit {
        version: uint32 &byte-order=spicy::ByteOrder::Little;

        on %done {
            print "0x%x" % self.version;
        }
    };

.. spicy-output:: basic-unit-parse-byte-order.spicy
    :exec: printf '\01\02\03\04' | spicy-driver %INPUT
    :show-with: foo.spicy

We see that unpacking the value has now flipped the bytes before
storing it in the ``version`` field.

Similar to ``%byte-order``, Spicy offers a variety of further
attributes that control the specifics of how fields are parsed. We'll
discuss them in the relevant sections throughout the rest of this
chapter.

.. rubric:: Non-type Fields

Unit fields always have a type. However, in some cases a field's type
is not explicitly declared, but derived from what's being parsed. The
main example of this is parsing a constant value: Instead of a type, a
field can specify a constant of a parseable type. The field's type
will then (usually) just correspond to the constant's type, and
parsing will expect to find the corresponding value in the input
stream. If a different value gets unpacked instead, parsing will abort
with an error. Example:

.. spicy-code:: constant-field.spicy

    module Test;

    public type Foo = unit {
        bar: b"bar";
        on %done { print self.bar; }
    };

.. spicy-output:: constant-field.spicy 1
    :exec: printf 'bar' | spicy-driver %INPUT
    :show-with: foo.spicy

.. spicy-output:: constant-field.spicy 2
    :exec: printf 'foo' | spicy-driver %INPUT
    :show-with: foo.spicy
    :expect-failure:

:ref:`Regular expressions <parse_regexp>` extend this scheme a bit
further: If a field specifies a regular expression constant rather
than a type, the field will have have type :ref:`type_bytes` and store
the data that ends up matching the regular expression:

.. spicy-code:: regexp.spicy

    module Test;

    public type Foo = unit {
        x: /Foo.*Bar/;
        on %done { print self; }
    };

.. spicy-output:: regexp.spicy
    :exec: printf 'Foo12345Bar' | spicy-driver %INPUT
    :show-with: foo.spicy

There's also a programmatic way to change a field's type to something
that's different than what's being parsed, see the
:ref:`attribute_convert`.

.. _attribute_size:

.. rubric:: Limiting Input Size

You can limit the input that a field receives by attaching a
``&size=EXPR`` attribute that specifies the number of raw bytes to
make available. This works on top of any other attributes that control
the field's parsing. From the field's perspective, such a size limit
acts just like reaching the end of the input stream at the specified
position. Example:

.. spicy-code:: size.spicy

    module Test;

    public type Foo = unit {
        x: int16[] &size=6;
        y: bytes &eod;
        on %done { print self; }
    };

.. spicy-output:: size.spicy
    :exec: printf '\000\001\000\002\000\003xyz' | spicy-driver %INPUT
    :show-with: foo.spicy

As you can see, ``x`` receives 6 bytes of input, which it then turns
into three 16-bit integers.

Normally, the field must consume all the bytes specified by ``&size``,
otherwise a parse error will be triggered. Some types support an
additional ``&eod`` attribute to lift this restrictions; we discuss
that in the corresponding type's section where applicable.

After a field with a ``&size=EXPR`` attribute, parsing will always
move ahead the full amount of bytes, even if the field permitted to
not consume them all.

.. todo::

    Parsing a regular expression would make a nice exmaple for
    ``&size`` as well, but we currently have a bug there
    (:issue:`286`).

.. rubric:: Anonymous Fields

Field names are optional. If skipped, the field becomes an *anonymous*
field. These still participate in parsing as any other field, but they
won't store any value, nor is there a way to get access to them from
outside. You can however still get to the parsed value inside a
corresponding field hook (see :ref:`unit_hooks`) using the reserved
``$$`` identifier (see :ref:`id_dollardollar`).

.. spicy-code:: anonymous-field.spicy

    module Test;

    public type Foo = unit {
        x: int8;
         : int8 { print $$; } # anonymous field
        y: int8;
        on %done { print self; }
    };

.. spicy-output:: anonymous-field.spicy
    :exec: printf '\01\02\03' | spicy-driver %INPUT
    :show-with: foo.spicy

.. _id_dollardollar:
.. _id_self:

.. rubric:: Reserved Identifiers

Inside units, two reserved identifiers provide access to values
currently being parsed:

``self``
    Inside a unit's type definition, ``self`` refers to the unit
    instance that's currently being processed. The instance is
    writable and maybe modified by assigning to any fields of
    ``self``.

``$$``
    Inside field attributes and hooks, ``$$`` refers to the just
    parsed value, even if it's not going to be directly stored in the
    field. The value of ``$$`` is writable and may be modified.

.. _attribute_convert:

.. rubric:: On-the-fly Type Conversion with ``&convert``

Fields may use an attribute ``&convert=EXPR`` to transform the value
that was just being parsed before storing it as the field's final
value. With the attribute being present, it's the value of ``EXPR``
that's stored in the field, not the parsed value. Accordingly, the
field's type also changes to the type of ``EXPR``.

Typically, ``EXPR`` will use ``$$`` to access the value actually being
parsed and then transform it into the desired representation. For
example, the following stores an integer parsed in an ASCII
representation as a ``uint64``:

.. spicy-code:: parse-convert.spicy

    module Test;

    import spicy;

    public type Foo = unit {
        x: bytes &eod &convert=$$.to_uint();
        on %done { print self; }
    };

.. spicy-output:: parse-convert.spicy
    :exec: printf 12345 | spicy-driver %INPUT
    :show-with: foo.spicy


.. _unit_hooks:

Unit Hooks
===========

Unit hooks provide one of the most powerful Spicy tools to control
parsing, track state, and retrieve results. Generally, hooks are
blocks of code triggered to execute at certain points during parsing,
with access to the current unit instance.

Conceptually, unit hooks are somewhat similar to methods: They have
bodies that execute when triggered, and these bodies may receive a set
of parameters as input. Different from functions, however, a hook can
have more than one body. If multiple implementations are provided for
the same hook, all of them will execute successively. A hook may also
not have any body implemented at all, in which case there's nothing to
do when it executes.

The most commonly used hooks are:

``on %init() { ... }``
    Executes just before unit parsing will start.

``on %done { ... }``
    Executes just after unit parsing has completed.

.. _on_error:

``on %error  { ... }``
    Executes when a parse error has been encountered, just before the
    parser either aborts processing.

``on <field name> { ... }`` (field hook)
    Executes just after the given unit field has been parsed. The
    parsed value is accessible through the ``$$`` identifier. It will
    also have been assigned to the field already, potentially with any
    relevant type conversion applied (see :ref:`attribute_convert`).

.. _foreach:

``on <field name> foreach { ... }`` (container hook)
    Assuming the specified field is a container (e.g., a vector), this
    executes each time a new container element has been parsed, and
    just before it's been added to the container. The parsed element
    is accessible through the ``$$`` identifier, and can be modified
    before it's stored. The hook implementation may also use the
    :ref:`statement_stop` statement to abort container parsing,
    without the current element being added anymore.

In addition, Spicy provides a set of hooks specific to the ``sink``
type; we discuss these the :ref:`corresponding section <sinks>`.

There are three location where hooks can be implemented:

- Inside a unit, ``on <hook name> { ... }`` implements the hook of the
  given name::

    type Foo = unit {
        x: uint32;
        v: unint8[];

        on %init { ... }
        on x { ... }
        on v foreach { ... }
        on %done { ... }
    }

- Field and container hooks may be directly attached to their field,
  skipping the ``on ...`` part::

    type Foo = unit {
        x: uint32 { ... }
        v: unint8[] foreach { ... }
    }

- At the global module level, one can add hooks to any available unit
  type through ``on <unit type>::<hook name> { ... }``. With the
  definition of ``Foo`` above, this implements hooks externally::

      on Foo::%init { ... }
      on Foo::x { ... }
      on Foo::v foreach { ... }
      on Foo::%done { ... }

  External hooks work across module boundaries by qualifying the unit
  type accordingly. They provide a powerful mechanism to extend a
  predefined unit without changing any of its code.

.. note::

   When a hook executes, it has access to the current unit instance
   through the ``self`` identifier. The state of that instance will
   reflect where parsing is at at that time. In particular, any field
   that haven't been parsed yet, will remain unset. (You can use the
   ``?.`` unit operator to test if a field has received a value yet.)

Unit Variables
==============

In addition to unit field for parsing, you can also add further instance
variables to a unit type to store arbitrary state:

.. spicy-code:: unit-vars.spicy

    module Test;

    public type Foo = unit {
        on %init { print self; }
        x: int8 { self.a = "Our integer is %d" % $$; }
        on %done { print self; }

        var a: string;
    };

.. spicy-output:: unit-vars.spicy
    :exec: printf \05 | spicy-driver %INPUT
    :show-with: foo.spicy

Here, we assign a string value to ``a`` once we have parsed ``x`. The
final ``print`` shows the expected value. As you can also see, before
we assign anything, the variable's value is just empty: Spicy
initializes instances variables with well-defined defaults. If you
would rather leave a variable unset by default, you can add
`&optional`:

.. spicy-code:: unit-vars-optional.spicy

    module Test;

    public type Foo = unit {
        on %init { print self; }
        x: int8 { self.a = "Our integer is %d" % $$; }
        on %done { print self; }

        var a: string &optional;
    };

.. spicy-output:: unit-vars-optional.spicy
    :exec: printf \05 | spicy-driver %INPUT
    :show-with: foo.spicy

.. _unit_parameters:

Unit Parameters
===============

Unit types can receive parameters upon instantion, which will then be
available to any code inside the type's declaration:

.. spicy-code:: unit-params.spicy

    module Test;

    type Bar = unit(msg: string, mult: int8) {
        x: int8 &convert=($$ * mult);
        on %done { print "%s: %d" % (msg, self.x); }
    };

    public type Foo = unit {
        y: Bar("My multiplied integer", 5);
    };

.. spicy-output:: unit-params.spicy
    :exec: printf '\05' | spicy-driver %INPUT
    :show-with: foo.spicy

This example shows a typical idiom: We're handing parameters down to a
subunit through parameters it receives. Inside the submodule, we then
have access to the values passed in.

.. note:: It's usually not very useful to define a top-level parsing
   unit with parameters because we don't have a way to pass anything
   in through ``spicy-driver``. A custom host application could make
   use of them, though.

This works with subunits inside containers as well, though the
syntax is a bit peculiar:

.. spicy-code:: unit-params-vector.spicy

    module Test;

    type Bar = unit(mult: int8) {
        x: int8 &convert=($$ * mult);
        on %done { print self.x; }
    };

    public type Foo = unit {
        x: int8;
        y: (Bar(self.x))[]; # Element constructor must be in "(...)"
    };

.. spicy-output:: unit-params-vector.spicy
    :exec: printf '\05\01\02\03' | spicy-driver %INPUT
    :show-with: foo.spicy

Unit parameters follow the same passing conventions as :ref:`function
parameters <functions>`. In particular, they are read-only by default.
If the subunit wants to modify a parameter it receives, it needs
to be declared as ``inout`` (e.g., ``Bar(inout s: string)``).

.. note::

    A common use-case for unit parameters is passing the ``self`` of a
    higher-level unit down into a subunit::

        type Foo = unit {
            ...
            b: Bar(self);
            ...
        }

        type Bar = unit(foo: Foo) {
            # We now have access to any state in "foo".
        }

    That way, the subunit can for example store state directly in the
    parent.

.. _unit_meta_data:

Meta data
=========

Units can provide meta data about their semantics through *properties*
that both Spicy itself and host applications can access. One defines
properties inside the unit's type through either a ``%<property> =
<value>;`` tuple, or just as ``%<property>;`` if the property does not
take an argument. Currently, units support the following meta data
properties:

``%mime-type = STRING``
    A string of the form ``"<type>/<subtype>"`` that defines the MIME
    type for content the unit knows how to parse. This may include a
    ``*`` wildcard for either the type or subtype. We use a
    generalized notion of MIME types here that can include custom
    meanings. See :ref:`sinks` for more on how these MIME types are
    used to select parsers dynamically during runtime.

    You can specify this property more than once to associate a unit
    with multiple types.

``%description = STRING``
    A short textual description of the unit type (i.e., the parser
    that it defines). Host applications have access to this property,
    and ``spicy-driver`` includes the information into the list of
    available parsers that it prints with the ``--list-parsers``
    option.

``%port = PORT_VALUE``
    A :ref:`type_port` to associate this unit with. This property has
    no built-in effect, but host applications may make use of the
    information to decide which unit type to use for parsing a
    connection's payload.

Units support some further properties for other purposes, which we
introduce in the corresponding sections.

Parsing Types
=============

Several, but not all, of Spicy's :ref:`data types <types>` can be
parsed from binary data. In the following we summary the types that
can, along with any options they support to control specifics of how
they unpack binary representations.

.. _parse_address:

Address
^^^^^^^

Spicy parses :ref:`addresses <type_address>` from either 4 bytes of
input for IPv4 addresses, or 16 bytes for IPv6 addresses. To select
the type, a unit field of type ``addr`` must come with either an
``&ipv4`` or ``&ipv6`` attribute.

By default, addresses are assumed to be represented in network byte
order. Alternatively, a different byte order can be specified through
a ``&byte-order`` attribute specifying the desired
:ref:`spicy_byteorder`.

Example:

.. spicy-code:: parse-address.spicy

    module Test;

    import spicy;

    public type Foo = unit {
        ip: addr &ipv6 &byte-order=spicy::ByteOrder::Little;
        on %done { print self; }
    };

.. spicy-output:: parse-address.spicy
    :exec: printf '1234567890123456' | spicy-driver %INPUT
    :show-with: foo.spicy

.. _parse_bitfield:

Bitfield
^^^^^^^^

Bitfields parse an integer value of a given size, and then make
selected smaller bit ranges within that value available individually
through dedicated identifiers. For example, the following unit parses
4 bytes as an ``uint32`` and then makes the value of bit 0 available
as ``f.x1``, bits 1 to 2 as ``f.x2``, and bits 3 to 5 as ``f.x3``,
respectively:

.. spicy-code:: parse-bitfield.spicy

    module Test;

    public type Foo = unit {
        f: bitfield(32) {
            x1: 0;
            x2: 1..2;
            x3: 3..4;
        };

        on %done {
            print self.f.x1, self.f.x2, self.f.x3;
            print self;
        }
    };

.. spicy-output:: parse-bitfield.spicy
    :exec: printf '\01\02\03\04' | spicy-driver %INPUT
    :show-with: foo.spicy

Generally, a field ``bitfield(N)`` field is parsed like an
``uint<N>``. The field then supports dereferencing individual bit
ranges through their labels. The corresponding expressions
(``self.x.<id>``) have the same ``uint<N>`` type as the parsed value
itself, with the value shifted to the right so that the lowest
extracted bit becomes bit 0 of the returned value. As you can see in
the example, the type of the field itself becomes a tuple composed of
the values of the individual bit ranges.

By default, a bitfield assumes the underlying integer comes in network
byte order. You can specify a ``&byte-order`` attribute to change that
(e.g., ``bitfield(32) { ... } &byte-order=spicy::ByteOrder::Little``).
Furthermore, each bit range can also specify a ``&bit-order``
attribute to specify the :ref:`ordering <spicy_bitorder>` for its
bits; the default is ``spicy::BitOrder::LSB0``.

The individual bit ranges support the ``&convert`` attribute and will
adjust their types accordingly, just like a regular unit field (see
:ref:`attribute_convert`). For example, that allows for mapping a bit
range to an enum, using ``$$`` to access the parsed value:

.. spicy-code:: parse-bitfield-enum.spicy

    module Test;

    import spicy;

    type X = enum { A = 1, B = 2 };

    public type Foo = unit {
        f: bitfield(8) {
            x1: 0..3 &convert=X($$);
            x2: 4..7 &convert=X($$);
        } { print self.f.x1, self.f.x2; }
    };

.. spicy-output:: parse-bitfield-enum.spicy
    :exec: printf '\41' | spicy-driver %INPUT
    :show-with: foo.spicy

.. _parse_bytes:

Bytes
^^^^^

When parsing a field of type :ref:`type_bytes`, Spicy will consume raw
input bytes according to a specified attribute that determines when to
stop. The following attributes are supported:

``&eod``
    Consumes all subsequent data until the end of the input is reached.

``&size=N``
    Consumes exactly ``N`` bytes. The attribute may be combined with
    ``&eod`` to consume up to ``N`` bytes instead (i.e., permit
    running out of input before the size limit is reached).

    (This attribute :ref:`works for fields of all types
    <attribute_size>`. We list it here because it's particularly
    common to use it with `bytes`.)

``&until=DELIM``
    Consumes bytes until the specified delimiter is found. ``DELIM``
    must be of type ``bytes`` itself. The delimiter will not be
    included into the resulting value.

``&until-including=DELIM``
    Similar to ``&until``, but this does include the delimiter
    ``DELIM`` into the resulting value.

One of these attributes must be provided.

On top of that, bytes fields support the attribute ``&chunked`` to
change how the parsed data is processed and stored. Normally, a bytes
field will first accumulate all desired data and then store the final,
complete value in the field. With ``&chunked``, if the data arrives
incrementally in pieces, the field instead processes just whatever is
available at a time, storing each piece directly, and individually, in
the field. Each time a piece gets stored, any associated field hooks
execute with the new part as their ``$$``. Parsing with ``&chunked``
will eventually still consume the same number of bytes overall, but it
avoids buffering everything in cases where that's either infeasible or
simply not not needed.

.. note::

    ``&chunked`` can currently not be combined with ``&until`` or
    ``&until-including``.

Bytes fields support parsing constants: If a ``bytes`` constant is
specified instead of a field type, parsing will expect to find the
corresponding value in the input stream.

.. _parse_integer:

Integer
^^^^^^^

Fields of :ref:`integer type <type_integer>` can be either signed
(``intN``) or unsigned (``uintN``). In either case, the bit length
``N`` determines the number of bytes being parsed. By default,
integers are expected to come in network byte order. You can specify a
different order through the ``&byte-order=ORDER`` attribute, where
``ORDER`` is of type :ref:`spicy_ByteOrder`.

Integer fields support parsing constants: If an integer constant is
specified instead the instead of a field type, parsing will expect to
find the corresponding value in the input stream. Since the exact type
of the integer constant is important, you should use their constructor
syntax to make that explicit (e.g., ``uint32(42)``, ``int8(-1)``; vs.
using just ``42`` or ``-1``).

.. _parse_real:

Real
^^^^

Real values are parsed as either single or double precision values in
IEEE754 format, depending on the value of their ``&type=T`` attribute,
where ``T`` is one of :ref:`spicy_RealType`.

.. _parse_regexp:

Regular Expression
^^^^^^^^^^^^^^^^^^

When parsing a field through a :ref:`type_regexp` , the expression is
expected to match at the current position of the input stream. The
field's type becomes ``bytes``, and it will store the matching data.
Matching is non-greedy(!): the first (shortest) match will satisfy the
parser.

.. _parse_unit:

Unit
^^^^

Fields can have the type of another unit, in which case parsing will
descend into that subunit's grammar until that instance has been fully
parsed. Field initialization and hooks work as usual.

If the subunit receives parameters, they must be given right after the
type.

.. spicy-code:: parse-unit-params.spicy

    module Test;

    type Bar = unit(a: string) {
        x: uint8 { print "%s: %u" % (a, self.x); }
    };

    public type Foo = unit {
        y: Bar("Spicy");
        on %done { print self; }
    };

.. spicy-output:: parse-unit-params.spicy
    :exec: printf '\01\02' | spicy-driver %INPUT
    :show-with: foo.spicy

See :ref:`unit_parameters` for more.

.. _parse_vector:

Vector
^^^^^^

Parsing a :ref:`vector <type_vector>` creates a loop that repeatedly
parses elements of the specified type from the input stream until an
end condition is reached. The field's value accumulates all the
elements into the final vector.

Spicy uses a specific syntax to define fields of type vector::

    NAME : ELEM_TYPE[SIZE].

``NAME`` is the field name as usual. ``ELEM_TYPE`` is type of the
vector's elements, i.e., the type that will be repeatedly parsed.
``SIZE`` is the number of elements to parse into the vector; this is
an arbitrary Spicy expression yielding an integer value. The resulting
field type then will be ``vector<ELEM_TYPE>``. Here's a simple example
parsing five ``uint8``:

.. spicy-code:: parse-vector.spicy

    module Test;

    public type Foo = unit {
        x: uint8[5];
        on %done { print self; }
    };

.. spicy-output:: parse-vector.spicy
    :exec: printf '\01\02\03\04\05' | spicy-driver %INPUT
    :show-with: foo.spicy

It is possible to skip the ``SIZE`` (e.g., ``x: uint8[]``) and instead
use another kind of end conditions to terminate a vector's parsing
loop. To that end, vectors support the following attributes:

``&size=N``
    Parses the vector from the subsequent ``N`` bytes of input data.
    This effectively limits the available input to the corresponding
    window, letting the vector parse elements until it runs out of
    data. (This attribute :ref:`works for fields of all types
    <attribute_size>`. We list it here because it's particularly
    common to use it with vectors.)

``&until=EXPR``
    Parses elements until one with the value ``EXPR`` is encountered.
    ``EXPR`` must be of the same type as the vector's elements. Once
    the specified element is encountered, vector parsing stops
    *without* including the matching one into the field's vector
    value.

``&until-including=EXPR``
    Similar to ``&until``, but does include the final element ``EXPR``
    into the field's vector when stopping parsing.

``&while=EXPR``
    Continues parsing as long as the boolean expression ``EXPR``
    evaluates to true.

If neither a size nor an attribute is given, Spicy will attempt to use
:ref:`look-ahead parsing <parse_lookahead>` to determine the end of
the vector based on the next expected token. Depending on the unit's
field, this may not be possible, in which case Spicy will decline to
compile the unit.

The syntax shown above generally works for all element types,
including subunits (e.g., ``x: MyUnit[]``). The one exception that
requires special syntax are units with parameters. In that case, one
needs to wrap the ``ELEM_TYPE`` in additional parentheses, and then
add the parameters to it (e.g., ``x: (MyUnit("arg1"))[]``).

.. _hook_foreach:

When parsing a vector, Spicy supports using a special kind of field
hook, ``foreach``, that executes for each parsed element individually.
Inside that hook, ``$$`` refers to the just parsed element:

.. spicy-code:: parse-vector-foreach.spicy

    module Test;

    public type Foo = unit {
        x: uint8[5] foreach { print $$, self.x; }
    };

.. spicy-output:: parse-vector-foreach.spicy
    :exec: printf '\01\02\03\04\05' | spicy-driver %INPUT
    :show-with: foo.spicy

As you can see, when a ``foreach`` hook executes the element has not yet
been added to the vector. You may indeed use a ``stop`` statement
inside a ``foreach`` hook to abort the vector's parsing without adding
the current element anymore. See :ref:`unit_hooks` for more on hooks.

.. _parse_void:

Void
^^^^

The :ref:`type_void` type can be used as a place-holder for not
parsing anything. While that's not very useful for normal fields, it
allows branches in :ref:`switch <parse_switch>` constructs to forego
any parsing.

Controlling Parsing
===================

Spicy offers a few additional constructs inside a unit's declaration
for steering the parsing process. We discuss them in the following.

.. _parse_lookahed:

Conditional Parsing
^^^^^^^^^^^^^^^^^^^

A unit field may be conditionally skipped for parsing by adding an
``if ( COND )`` clause, where ``COND`` is a boolean expression. The
field will be only parsed if the expression evaluates to true at the
time the field is next in line.

.. spicy-code:: parse-if.spicy

    module Test;

    public type Foo = unit {
        a: int8;
        b: int8 if ( self.a == 1 );
        c: int8 if ( self.a % 2 == 0 );
        d: int8;

        on %done { print self; }
    };

.. spicy-output:: parse-if.spicy
    :exec: printf '\01\02\03\04' | spicy-driver %INPUT; printf '\02\02\03\04' | spicy-driver %INPUT
    :show-with: foo.spicy

.. _parse_lookahead:

Look-Ahead
^^^^^^^^^^

Internally, Spicy builds an LR(1) grammar for each unit that it
parses, meaning that it can actually look *ahead* in the parsing
stream to determine how to process the current input location. Roughly
speaking, if (1) the current construct does not have a clear end
condition defined (such a specific length), and (2) a specific value
is expected to be found next; then the parser will keep looking for
that value and end the current construct once it finds it.

"Construct" deliberately remains a bit of a fuzzy term here, but think
of vector parsing as the most common instance of this: If you don't
give a vector an explicit termination condition (as discussed in
:ref:`parse_vector`), Spicy will look at what's expected to come
*after* the container. As long as that's something clearly
recognizable (e.g., a specific value of an atomic type, or a match for
a regular expression), it'll terminate the vector accordingly.

Here's an example:

.. spicy-code:: parse-look-ahead.spicy

    module Test;

    public type Foo = unit {
        data: uint8[];
            : /EOD/;
        x   : int8;

        on %done { print self; }
    };

.. spicy-output:: parse-look-ahead.spicy
    :exec: printf '\01\02\03EOD\04' | spicy-driver %INPUT
    :show-with: foo.spicy

For vectors, Spicy attempts look-ahead parsing automatically as a last
resort when it doesn't find more explicit instructions. However, it
will reject a unit if it can't find a suitable look-ahead symbol to
work with. If we had written ``int32`` in the example above, that
would not have worked as the parser can't recognize when there's a
``int32`` coming; it would need to be a concrete value, such as
``int32(42)``.

See the :ref:`parse_switch` construct for another instance of
look-ahead parsing.

.. _parse_switch:

``switch``
^^^^^^^^^^

Spicy supports a ``switch`` construct as way to branch into one
of several parsing alternatives. There are two variants of this, a
explicit branch and one driving by look-ahead:

.. rubric:: Branch by expression

The most basic form of switching by expression looks like this::

    switch ( EXPR ) {
        VALUE_1 -> FIELD_1;
        VALUE_2 -> FIELD_2;
        ...
        VALUE_N -> FIELD_N``
    };

This evaluates ``EXPR`` at the time parsing reaches the ``switch``. If
there's a ``VALUE`` matching the result, parsing continues with the
corresponding field, and then proceeds with whatever comes after the
switch. Example:

.. spicy-code:: parse-switch.spicy

    module Test;

    public type Foo = unit {
        x: bytes &size=1;
        switch ( self.x ) {
            b"A" -> a8: int8;
            b"B" -> a16: int16;
            b"C" -> a32: int32;
        };

        on %done { print self; }
    };

.. spicy-output:: parse-switch.spicy
    :exec: printf 'A\01' | spicy-driver %INPUT; printf 'B\01\02' | spicy-driver %INPUT
    :show-with: foo.spicy

We see in the output that all of the alternatives turn into normal
unit members, with all but the one for the branch that was taken left
unset.

If none of the values match the expression, that's considered a
parsing error and processing will abort. Alternative, one can add a
default alternative by using ``*`` as the value. The branch will then
be taken whenever no other value matches.

A couple additional notes about the fields inside an alternative:

    - In our example, the fields of all alternatives all have
      different names, and they all show up in the output. One can
      also reuse names across alternatives as long as the types
      exactly match. In that case, the unit will end up with only a
      single instance of that member.

    - An alternative can match against more than one value by
      separating them with commas (e.g., ``b"A", b"B" -> x: int8;``).

    - Alternatives can have more than one field attached by enclosing
      them in braces, i.e.,: ``VALUE -> { FIELD_1a; FIELD_1b; ...;
      FIELD_1n; }``.

    - Sometimes one really just needs the branching capability, but
      doesn't have any field values to store. In that case an
      anonymous ``void`` field may be helpful( e.g., ``b"A" -> : void
      { DoSomethingHere(); }``.

.. rubric:: Branch by look-ahead

``switch`` also works without any expression as long as the presence
of all the alternatives can be reliably recognized by looking ahead in
the input stream:

.. spicy-code:: parse-switch-lhead.spicy

    module Test;

    public type Foo = unit {
        switch {
            a: b"A";
            b: b"B";
            c: b"C";
        };

        on %done { print self; }
    };

.. spicy-output:: parse-switch-lhead.spicy
    :exec: printf 'A' | spicy-driver %INPUT
    :show-with: foo.spicy

While this example is a bit contrived, the mechanisms becomes powerful
once you have subunits that are recognizable by how they start:

.. spicy-code:: parse-switch-lhead-2.spicy

    module Test;

    type A = unit {
        a: b"A";
    };

    type B = unit {
        b: uint16(0xffff);
    };

    public type Foo = unit {
        switch {
            a: A;
            b: B;
        };

        on %done { print self; }
    };

.. spicy-output:: parse-switch-lhead-2.spicy
    :exec: printf 'A ' | spicy-driver %INPUT; printf '\377\377' | spicy-driver %INPUT
    :show-with: foo.spicy


Changing Input
==============

By default, a Spicy parser proceeds linearly through its inputs,
parsing as much as it can and yielding back to the host application
once it runs out of input. There are two ways to change this linear
model: diverting parsing to a different input, and random access
within the current unit's data.

.. rubric:: Parsing custom data

A unit field can have either ``&parse-from=EXPR`` or
``&parse-at=EXPR`` attached to it to change where it's receiving its
data to parse from. ``EXPR`` is evaluated at the time the field is
reached. For ``&parse-from`` it must produce a value of type
``bytes``, which will then constitute the input for the field. This
can, e.g., be used to reparse previously received input:

.. spicy-code:: parse-parse.spicy

    module Test;

    public type Foo = unit {
        x: bytes &size=2;
        y: uint16 &parse-from=self.x;
        z: bytes &size=2;

        on %done { print self; }
    };

.. spicy-output:: parse-parse.spicy
    :exec: printf '\x01\x02\x03\04' | spicy-driver %INPUT
    :show-with: foo.spicy

For ``&parse-at``, ``EXPR`` must yield an iterator pointing to (a
still valid) position of the current unit's input stream (such as
retrieved through spicy:method:`unit::input`). The field will then be
parsed from the data starting at that location.

.. _random_access:

.. rubric:: Random access

While a unit is being parsed, you may revert the current input
position backwards to any location between the first byte the unit has
has seen and the current position. To enable this functionality, the
unit needs to be declared with the ``%random-access`` property. You
can use a set of built-in unit methods to control the current position:

:spicy:method:`unit::input`
    Returns a stream iterator pointing to the current input position.

:spicy:method:`unit::set_input`
    Sets the current input position to the location of the specified
    stream iterator. Per above, the new position needs to reside
    between the beginning of the current unit's data and the current
    position; otherwise an exception will be generated at runtime.

:spicy:method:`unit::offset`
    Returns the numerical offset of the current input position
    relative to position of the first byte fed into this unit.

For random access, you'd typically get the current position through
``input()``, subtract from it the desired number of bytes you want to
back, and then use ``set_input`` to establish that new position. By
further storing iterators as unit variables you can decouple these
steps and, e.g., remember a position to later come back to.

Here's an example that parses input data twice with different sub units:

.. spicy-code:: parse-random-access.spicy

    module Test;

    public type Foo = unit {
        %random-access;

        on %init() { self.start = self.input(); }

        a: A { self.set_input(self.start); }
        b: B;

        on %done() { print self; }

        var start: iterator<stream>;
    };

    type A = unit {
        x: uint32;
    };

    type B = unit {
        y: bytes &size=4;
    };


.. spicy-output:: parse-random-access.spicy
    :exec: printf '\00\00\00\01' | spicy-driver %INPUT
    :show-with: foo.spicy

If you look at output, you see that ``start`` iterator remembers it's
offset, relative to the global input stream. It would also show the
data at that offset if the parser had not already discarded that at
the time we print it out.

.. note::

   Spicy parsers discard input data as quickly as possible as parsing
   moves through the input stream. Indeed, that's why using random
   access may come with a performance penality as the parser now needs
   to buffer all of unit's data until it has been fully processed.

.. _filters:

Filters
=======

Spicy supports attaching *filters* to units that get to preprocess and
transform a unit's input before its parser gets to see it. A typical
use case for this is stripping off a data encoding, such as
compression or Base64.

A filter is itself just a ``unit`` that comes with an additional property
`%filter` marking it as such. The filter unit's input represents the
original input to be transformed. The filter calls an internally
provided unit method :spicy:method:`unit::forward` to pass any
transformed data on to the main unit that it's attached to. The filter
can call ``forward`` arbitrary many times, each time forwarding a
subsequent chunk of input. To attach a filter to a unit, one calls the
method :spicy:method:`unit::connect_filter` with an instance of the
filter's type. Putting that all together, this is an example of simple
a filter that upper-cases all input before the main parsing unit gets
to see it:

.. spicy-code:: parse-filter.spicy

    module Test;

    type Filter = unit {
        %filter;

        : bytes &eod &chunked {
            self.forward($$.upper());
        }
    };

    public type Foo = unit {
        on %init { self.connect_filter(new Filter); }
        x: bytes &size=5 { print self.x; }
    };

.. spicy-output:: parse-filter.spicy
    :exec: printf 'aBcDe' | spicy-driver %INPUT
    :show-with: foo.spicy

There are a couple of predefined filters coming with Spicy that become
available by importing the ``filter`` library module:

``filter::Zlib``
    Provides zlib decompression.

``filter::Base64Decode``
    Provides base64 decoding.

.. _sinks:

Sinks
=====

Sinks provide a powerful mechanism to chain multiple units together
into a layered stack, each processing the output of its predecessor. A
sink is the connector here that links to unit instances, with one side
writing and one side reading like a Unix pipe. As additional
functionality, the sink can internally reassemble data chunks that are
arriving out of order before passing anything on.

Here's a basic example of two units types chained through a sink:

.. spicy-code:: parse-sink.spicy

    module Test;

    public type A = unit {
        on %init { self.b.connect(new B); }

        length: uint8;
        data: bytes &size=self.length { self.b.write($$); }

        on %done { print "A", self; }

        sink b;
    };

    public type B = unit {
            : /GET /;
        path: /[^\n]+/;

        on %done { print "B", self; }
    };

.. spicy-output:: parse-sink.spicy
    :exec: printf '\13GET /a/b/c\n' | spicy-driver -p Test::A %INPUT
    :show-with: foo.spicy

.. note:: Sinks must be declared ``public`` currently. That's a
   restriction that we may eventually remove.

Let's see what's going on here. First, there's ``sink b`` inside the
declaration of ``A``. That's the connector, kept as state inside
``A``. When parsing for ``A`` is about to begin, the ``%init`` hook
connects the sink to a new instance of ``B``; that'll be the receiver
for data that ``A`` is going to write into the sink. That writing
happens inside the field hook for ``data``: once we have parsed that
field, we write what will go to the sink using its built-in
:spicy:method:`sink::write` method. With that write operation, the
data will emerge as input for the instance of ``B`` that we created
earlier, and that will just proceed parsing it normally. As the output
shows, in the end both unit instances end up having their fields set.

As an alternative for using the :spicy:method:`sink::write` in the
example, there's some syntactic sugar for fields of type ``bytes``
(like ``data`` here): We can just replace the hook with a ``->``
operator to have the parsed data automatically be forwarded to the
sink: ``data: bytes &size=self.length -> self.b``.

Sinks have a number of further methods, see :ref:`type_sink` for the
complete reference. Most of them we will also encounter in the
following when discussing additional functionality that sinks provide.

Using Filters
^^^^^^^^^^^^^

Sinks also support :ref:`filters <filters>` to preprocess any data
they receive before forwarding it on. This works just like for units
by calling the built-in sink method
:spicy:method:`sink::connect_filter`. For example, if in the example
above, ``data`` would have been gzip compressed, we could have
instructed the sink to automatically decompress it by calling
``self.b.connect_filter(new filter::Zlib)`` (leveraging the
Spicy-provided ``Zlib`` filter).

Leveraging MIME Types
^^^^^^^^^^^^^^^^^^^^^

In our example above we knew which type of unit we wanted to connect.
In practice, that may or may not be the case. Often, it only becomes
clear at runtime what the choice for the next layer should be, such as
when using well-known ports to determine the appropriate
application-layer analyzer for a TCP stream. Spicy supports dynamic
selection through a generalized notion of MIME types: Units can
declare which MIME types they know how to parse (see
:ref:`unit_meta_data`) , and sinks have
:spicy:method:`sink::connect_mime_type` method that will instantiate and
connect any that match their argument (if that's multiple, all we
connected and all will receive the same data).

"MIME type" can mean actual MIME types, such ``text/html``.
Applications can, however, also define their own notion of
``<type>/<subtype>`` to model other semantics. For example, one could
use ``x-port/443`` as convention to trigger parsers by well-known
port. An SSL unit would then declare ``%mime-type = "x-port/443``, and
the connection would be established through the equivalent of
``connect_mime("x-port/%d" % resp_port_of_connection)``.

.. todo:

    For this specific example, there's a better solution: We also have
    the ``%port`` property and should just build up a table index on
    that.

Reassembly
^^^^^^^^^^

Reassembly (or defragmentation) of out-of-order data chunks is a common requirement
for many protocols. Sinks have that functionality built-in by
allowing you to associate a position inside a virtual sequence space with each
chunk of data. Sinks will then pass their data on to
connected units only once they have collected a continuous, in-order range of bytes.

The easiest way to leverage this
is to simply associate sequence numbers with each
:spicy:method:`sink::write` operation:

.. spicy-code:: parse-reassembly.spicy

    module Test;

    public type Foo = unit {

        sink data;

        on %init {
            self.data.connect(new Bar);
            self.data.write(b"567", 5);
            self.data.write(b"89", 8);
            self.data.write(b"012", 0);
            self.data.write(b"34", 3);
        }
    };

    public type Bar = unit {
        s: bytes &eod;
        on %done { print self.s; }
    };

.. spicy-output:: parse-reassembly.spicy
    :exec: spicy-driver -p Test::Foo %INPUT </dev/null
    :show-with: foo.spicy


By default, Spicy expects the sequence space to start at zero, so the
first byte of the input stream needs to be passed in with sequence
number zero. You can change that base number by calling the
sink method :spicy:method:`sink::set_initial_sequence_number`. You can
control Spicy's gap handling, including when to stop buffering data
because you know nothing further will arrive anymore. Spicy can also
notify you about unsuccessful reassembly through a series of built-in unit hooks.
See :ref:`type_sink` for a reference of the available functionality.
