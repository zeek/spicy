
.. _parsing:

=======
Parsing
=======

Basics
======

Type Declaration
^^^^^^^^^^^^^^^^

Spicy expresses units of data to parse through a type called,
appropriately, ``unit``. At a high level, a unit is similar to structs
or records in other languages: It defines an ordered set of fields,
each with a name and a type, that during runtime will store
corresponding values. Units can be instantiated, fields can be
assigned values, and these values can then be retrieved. Here's about
the most basic Spicy unit one can define:

.. spicy-code::

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
    :exec: spicyc -j -d %INPUT

Fields are initially unset, and attempting to read an unset field will
trigger a :ref:`runtime error <error_handling>`. You may, however,
provide a default value by adding a ``&default`` *attribute* to the
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
    :exec: spicyc -j -d %INPUT

Note how the field remains unset even with the default now specified,
while the access returns the expected value.

.. note::

    During development, we recommend running `spicy-driver` with the
    ``--debug`` option (``-d`` for short) to prevent the optimizer
    from being too aggressive and eliding fields it considers unused.
    For example, if we had run the first example above without
    ``-d``, the output would have looked like this:

    .. spicy-output:: basic-unit-module.spicy 2
        :exec: spicyc -j %INPUT

    In the following, we will generally run with ``-d``. Once a parser
    is ready for production, you would omit this option to get the
    best performance. See :ref:`optimization` for more on this topic.

Parsing a Field
^^^^^^^^^^^^^^^

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
    :exec: printf '\01\02\03\04' | spicy-driver -d %INPUT
    :show-with: foo.spicy

The output comes of course from the ``print`` statement inside the
``%done`` hook, which executes once the unit has been fully parsed.
(We will discuss unit hooks further below.)

.. _attribute_order:

By default, Spicy assumes integers that it parses to be represented in
network byte order (i.e., big-endian), hence the output above.
Alternatively, we can tell the parser through an attribute that our
input is arriving in, say, little-endian instead. To do that, we
import the ``spicy`` library module, which provides an enum type
:ref:`spicy_byteorder` that we can give to a ``&byte-order`` field
attribute for fields that support it:

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
    :exec: printf '\01\02\03\04' | spicy-driver -d %INPUT
    :show-with: foo.spicy

We see that unpacking the value has now flipped the bytes before
storing it in the ``version`` field.

Similar to ``&byte-order``, Spicy offers a variety of further
attributes that control the specifics of how fields are parsed. We'll
discuss them in the relevant sections throughout the rest of this
chapter.

Non-type Fields
^^^^^^^^^^^^^^^

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
    :exec: printf 'bar' | spicy-driver -d %INPUT
    :show-with: foo.spicy

.. spicy-output:: constant-field.spicy 2
    :exec: printf 'foo' | spicy-driver -d %INPUT
    :show-with: foo.spicy
    :expect-failure:

:ref:`Regular expressions <parse_regexp>` extend this scheme a bit
further: If a field specifies a regular expression constant rather
than a type, the field will have type :ref:`type_bytes` and store
the data that ends up matching the regular expression:

.. spicy-code:: regexp.spicy

    module Test;

    public type Foo = unit {
        x: /Foo.*Bar/;
        on %done { print self; }
    };

.. spicy-output:: regexp.spicy
    :exec: printf 'Foo12345Bar' | spicy-driver -d %INPUT
    :show-with: foo.spicy

There's also a programmatic way to change a field's type to something
that's different than what's being parsed, see the
:ref:`&convert attribute <attribute_convert>`.

.. _attribute_size:

Parsing Fields With Known Size
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
    :exec: printf '\000\001\000\002\000\003xyz' | spicy-driver -d %INPUT
    :show-with: foo.spicy

As you can see, ``x`` receives 6 bytes of input, which it then turns
into three 16-bit integers.

Normally, the field must consume all the bytes specified by ``&size``,
otherwise a parse error will be triggered. Some types support an
additional ``&eod`` attribute to lift this restrictions; we discuss
that in the corresponding type's section where applicable.

After a field with a ``&size=EXPR`` attribute, parsing will always
move ahead the full amount of bytes, even if the field did not consume
them all.

.. todo::

    Parsing a regular expression would make a nice example for
    ``&size`` as well.

Defensively Limiting Input Size
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On their own, parsers place no intrinsic upper limit on the size of
variable-size fields or units. This can have negative effects like
out-of-memory errors, e.g., when available memory is constrained, or for
malformed input.

As a defensive mechanism you can put an upper limit on the data a field or unit
receives by attaching a ``&max-size=EXPR`` attribute where ``EXPR`` is an
unsigned integer specifying the upper limit of number of raw bytes a field or
unit should receive. If more than ``&max-size`` bytes are consumed during
parsing, an error will be triggered.  This attribute works on top of any other
attributes that control parsing. Example:

.. spicy-code:: max-size.spicy

    module Test;

    public type Foo = unit {
        x: bytes &until=b"\x00" &max-size=1024;
        on %done { print self; }
    };

.. spicy-output:: max-size.spicy
    :exec: printf '\001\002\003\004\005\000' | spicy-driver -d %INPUT
    :show-with: foo.spicy

Here ``x`` will parse a ``NULL``-terminated byte sequence (excluding the
terminating ``NULL``), but never more than 1024 bytes.

``&max-size`` cannot be combined with ``&size``.

.. _anonymous_fields:

Anonymous Fields
^^^^^^^^^^^^^^^^

Field names are optional. If skipped, the field becomes an *anonymous*
field. These still participate in parsing as any other field, but they
won't store any value, nor is there a way to get access to them from
outside. You can, however, still get to the field's final value inside
a corresponding field hook (see :ref:`unit_hooks`) using the reserved
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
    :exec: printf '\01\02\03' | spicy-driver -d %INPUT
    :show-with: foo.spicy

Anonymous fields can often be more efficient to process because the
parser doesn't need to retain their values. In particular for larger
``bytes`` fields, making them anonymous is recommended where possible
(unless, even better, they can be fully skipped over; see
:ref:`skip`).

.. _skip:

Skipping Input
^^^^^^^^^^^^^^

For cases where your parser just needs to skip over some data without
needing access to its content, Spicy provides a ``skip`` keyword to
prefix corresponding fields with:

.. spicy-code:: skip.spicy

    module Test;

    public type Foo = unit {
        x: int8;
         : skip bytes &size=5;
        y: int8;
        on %done { print self; }
    };

.. spicy-output:: skip.spicy
    :exec: printf '\01\02\03\04\05\06\07' | spicy-driver -d %INPUT
    :show-with: foo.spicy

``skip`` works for all kinds of fields but is particularly efficient
for fields of known size for which optimized code will be generating
avoiding the overhead of storing any data.

``skip`` fields may have conditions and hooks attached, like any other fields.
However, they do not support ``$$`` in expressions and hook.

Since ``skip`` allows the compiler to optimize the field's parsing
code---including completely eliding most of it---it remains undefined if any
side effects associated with the field will take effect. For example,
``&requires`` attributes might be ignored, ``&convert`` expressions might not
be evaluated, and hooks could end up not being invoked.

For readability, a ``skip`` field may be named (e.g., ``padding: skip
bytes &size=3;``), but even with a name, its value cannot be accessed.

.. _id_dollardollar:
.. _id_self:

Reserved Identifiers
^^^^^^^^^^^^^^^^^^^^

Inside units, two reserved identifiers provide access to values
currently being parsed:

``self``
    Inside a unit's type definition, ``self`` refers to the unit
    instance that's currently being processed. The instance is
    writable and maybe modified by assigning to any fields of
    ``self``.

``$$``
    Inside field attributes, ``$$`` refers to the value as it was
    parsed. Inside field hooks, ``$$`` refers to the final value
    *after* any conversions are applied (see
    :ref:`attribute_convert`). This applies even if the value is not
    going to be directly stored in the field. The value of ``$$`` is
    writable and may be modified.

.. note::

   ``$$`` has slightly different semantics in a field attribute and
   in a hook. In an attribute, ``$$`` refers to the parsed value
   *before* any conversions. In a hook, ``$$`` refers to the final
   value *after* any conversions.

.. _attribute_convert:

On-the-fly Type Conversion with &convert
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Fields may use an attribute ``&convert=EXPR`` to transform the value
that was just being parsed before storing it as the field's final
value. With the attribute being present, it's the value of ``EXPR``
that's stored in the field, not the parsed value. Accordingly, the
field's type also changes to the type of ``EXPR``.

Typically, ``EXPR`` will use ``$$`` to access the parsed value and
then transform it into the desired representation. For example, the
following stores an integer parsed in an ASCII representation as a
``uint64``:

.. spicy-code:: parse-convert.spicy

    module Test;

    import spicy;

    public type Foo = unit {
        x: bytes &eod &convert=$$.to_uint();
        on %done { print self; }
    };

.. spicy-output:: parse-convert.spicy
    :exec: printf 12345 | spicy-driver -d %INPUT
    :show-with: foo.spicy

``&convert`` also works at the unit level to transform a whole
instance into a different value after it has been parsed:

.. spicy-code:: parse-convert-unit.spicy

    module Test;

    type Data = unit {
        data: bytes &size=2;
    } &convert=self.data.to_int();

    public type Foo = unit {
        numbers: Data[];

        on %done { print self.numbers; }
    };

.. spicy-output:: parse-convert-unit.spicy
    :exec: printf 12345678 | spicy-driver -d %INPUT
    :show-with: foo.spicy

Note how the ``Data`` instances have been turned into integers.
Without the ``&convert`` attribute, the output would have looked like
this::

    [[$data=b"12"], [$data=b"34"], [$data=b"56"], [$data=b"78"]]

.. _attribute_requires:

Enforcing Parsing Constraints
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Fields may use an attribute ``&requires=EXPR`` to enforce additional
constraints on their values. ``EXPR`` must yield a boolean value
and will be evaluated after the parsing for the field has finished,
but before any hooks execute. If ``EXPR`` returns ``False``, the
parsing process will abort with an error, just as if the field had
been unparsable in the first place (incl. executing any :ref:`%error
<on_error>` hooks). ``EXPR`` has access to the parsed value through
:ref:`$$ <id_dollardollar>`. It may also retrieve the field's final
value through ``self.<field>``, which can be helpful when
:ref:`&convert <attribute_convert>` is present.

Example:

.. spicy-code:: parse-requires.spicy

    module Test;

    import spicy;

    public type Foo = unit {
        x: int8 &requires=($$ < 5);
        on %done { print self; }
    };

.. spicy-output:: parse-requires.spicy 1
    :exec: printf '\001' | spicy-driver -d %INPUT
    :show-with: foo.spicy

.. spicy-output:: parse-requires.spicy 2
    :exec: printf '\010' | spicy-driver -d %INPUT
    :show-with: foo.spicy
    :expect-failure:

.. versionadded:: 1.12 Custom error messages

Instead of computing a boolean value directly, ``EXPR`` can also
leverage the :ref:`condition test operator <operator_condition_test>`
to provide a custom error message when the condition fails. Example:

.. spicy-code:: parse-requires-with-error.spicy

    module Test;

    import spicy;

    public type Foo = unit {
        x: int8 &requires=($$ < 5 : "x is too large"); # custom error message
        on %done { print self; }
    };

.. spicy-output:: parse-requires-with-error.spicy
    :exec: printf '\010' | spicy-driver -d %INPUT
    :show-with: foo.spicy
    :expect-failure:

One can also enforce conditions globally at the unit level through a attribute
``&requires = EXPR``. ``EXPR`` will be evaluated once the unit has been fully
parsed, but before any ``%done`` hook executes. If ``EXPR`` returns ``False``,
the unit's parsing process will abort with an error. As usual, ``EXPR`` has
access to the parsed instance through ``self``. More than one ``&requires``
attribute may be specified.

Example:

.. spicy-code:: parse-requires-property.spicy

    module Test;

    import spicy;

    public type Foo = unit {
        x: int8;
        on %done { print self; }
    } &requires = self.x < 5;


.. spicy-output:: parse-requires-property.spicy 1
    :exec: printf '\001' | spicy-driver -d %INPUT
    :show-with: foo.spicy

.. spicy-output:: parse-requires-property.spicy 2
    :exec: printf '\010' | spicy-driver -d %INPUT
    :show-with: foo.spicy
    :expect-failure:

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
    Executes just after unit parsing has completed successfully.

.. _on_error:

``on %error  { ... }`` or ``on %error(msg: string) { ... }``
    Executes when a parse error has been encountered, just before the
    parser either aborts processing. If the second form is used, a
    description of the error will be provided through the string
    argument.

``on %finally  { ... }``
    Executes once unit parsing has completed in any way. This hook is
    most useful to modify global state that needs to be updated no
    matter the success of the parsing process. Once `%init` triggers, this
    hook is guaranteed to eventually execute as well. It will run
    *after* either ``%done`` or ``%error``, respectively. (If a new
    error occurs during execution of ``%finally``, that will not
    trigger the unit's ``%error`` hook.)

``on %print  { ... }``
    Executes when a unit is about to be printed (and more generally:
    when rendered into a string representation). By default, printing
    a unit will produce a list of its fields with their current
    values. Through this hook, a unit can customize its appearance by
    returning the desired string.

``on <field name> { ... }`` (field hook)
    Executes just after the given unit field has been parsed. The
    final value is accessible through the ``$$``, potentially with
    any relevant type conversion applied (see
    :ref:`attribute_convert`). The same will also have been assigned
    to the field already.

.. _foreach:

``on <field name> foreach { ... }`` (container hook)
    Assuming the specified field is a container (e.g., a vector), this
    executes each time a new container element has been parsed, and
    just before it's been added to the container. The element's final
    value is accessible through the ``$$`` identifier, although it
    can be further modified before it's stored. The hook
    implementation may also use the :ref:`statement_stop` statement to
    abort container parsing, without the current element being added
    anymore.

In addition, Spicy provides a set of hooks specific to the ``sink`` type which
are discussed in the :ref:`section on sinks <sinks>`, and hooks which are
executed during :ref:`error recovery <error_recovery_hooks>`.

There are three locations where hooks can be implemented:

- Inside a unit, ``on <hook name> { ... }`` implements the hook of the
  given name:

  .. spicy-code::

    type Foo = unit {
        x: uint32;
        v: uint8[];

        on %init { ... }
        on x { ... }
        on v foreach { ... }
        on %done { ... }
    }

- Field and container hooks may be directly attached to their field,
  skipping the ``on ...`` part:

  .. spicy-code::

    type Foo = unit {
        x: uint32 { ... }
        v: uint8[] foreach { ... }
    }

- At the global module level, one can add hooks to any available unit
  type through ``on <unit type>::<hook name> { ... }``. With the
  definition of ``Foo`` above, this implements hooks externally:

  .. spicy-code::

      on Foo::%init { ... }
      on Foo::x { ... }
      on Foo::v foreach { ... }
      on Foo::%done { ... }

  External hooks work across module boundaries by qualifying the unit
  type accordingly. They provide a powerful mechanism to extend a
  predefined unit without changing any of its code.

If multiple implementations are provided for the same hook, by default
it remains undefined in which order they will execute. If a particular
order is desired, you can specify priorities for your hook
implementations:

.. spicy-code::

      on Foo::v priority=5 { ... }
      on Foo::v priority=-5 { ... }

Implementations then execute in order of their priorities: The higher a
priority value, the earlier it will execute. If not specified, a
hook's priority is implicitly taken as zero.

.. note::

   When a hook executes, it has access to the current unit instance
   through the ``self`` identifier. The state of that instance will
   reflect where parsing is at that time. In particular, any field
   that hasn't been parsed yet, will remain unset. You can use the
   ``?.`` unit operator to test if a field has received a value yet.

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
    :exec: printf \05 | spicy-driver -d %INPUT
    :show-with: foo.spicy

Here, we assign a string value to ``a`` once we have parsed ``x``. The
final ``print`` shows the expected value. As you can also see, before
we assign anything, the variable's value is just empty: Spicy
initializes unit variables with well-defined defaults. If you
would rather leave a variable unset by default, you can add
``&optional``:

.. spicy-code:: unit-vars-optional.spicy

    module Test;

    public type Foo = unit {
        on %init { print self; }
        x: int8 { self.a = "Our integer is %d" % $$; }
        on %done { print self; }

        var a: string &optional;
    };

.. spicy-output:: unit-vars-optional.spicy
    :exec: printf \05 | spicy-driver -d %INPUT
    :show-with: foo.spicy

You can use the ``?.`` unit operator to test if an optional unit variable
remains unset, e.g., ``self?.x`` would return ``True`` if field ``x`` is set
and ``False`` otherwise.

Unit variables can also be initialized with custom expressions when being
defined. The initialization is performed just before the containing unit starts
parsing (implying that the expressions cannot access parse results
of the unit itself yet)

.. spicy-code:: unit-vars-init.spicy

    module Test;

    public type Foo = unit {
        x: int8;
        var a: int8 = 123;
        on %done { print self; }
    };

.. spicy-output:: unit-vars-init.spicy
    :exec: printf \05 | spicy-driver -d %INPUT
    :show-with: foo.spicy

.. _unit_parameters:

Unit Parameters
===============

Unit types can receive parameters upon instantiation, which will then be
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
    :exec: printf '\05' | spicy-driver -d %INPUT
    :show-with: foo.spicy

This example shows a typical idiom: We're handing parameters down to a
subunit through parameters it receives. Inside the submodule, we then
have access to the values passed in.

.. note:: It's usually not very useful to define a top-level parsing
   unit with parameters because we don't have a way to pass anything
   in through ``spicy-driver``. A custom host application could make
   use of them, though.

This works with subunits inside containers as well:

.. spicy-code:: unit-params-vector.spicy

    module Test;

    type Bar = unit(mult: int8) {
        x: int8 &convert=($$ * mult);
        on %done { print self.x; }
    };

    public type Foo = unit {
        x: int8;
        y: Bar(self.x)[];
    };

.. spicy-output:: unit-params-vector.spicy
    :exec: printf '\05\01\02\03' | spicy-driver -d %INPUT
    :show-with: foo.spicy

A common use-case for unit parameters is passing the ``self`` of a
higher-level unit down into a subunit:

.. spicy-code::

    type Foo = unit {
        ...
        b: Bar(self);
        ...
    }

    type Bar = unit(foo: Foo) {
        # We now have access to any state in "foo".
    }

That way, the subunit can for example store state directly in the
parent. If you declare the ``foo`` parameter as ``inout``, the subunit
can also modify its members.

Unit parameters generally follow the same passing conventions as
:ref:`function parameters <functions>`, yet with some restrictions.
By default, just like with functions, parameters are read-only by
default. If you want the receiving unit to be able to modify the
value, there are two options:

1. If the parameter itself is a unit, you can declare it as ``inout``
   as described above.

2. For all other types, you instead need to pass the parameter as a
   :ref:`reference <type_reference>`. Here's an example passing a
   string so that it can be modified by the subunit:

    .. spicy-code:: unit-params-string.spicy

        module Test;

        type X = unit(s: string&) {
            n: uint8 {
                *s = "Hello, world!";
               }
        };

        public type Y = unit {
            x: X(self.s);

            on %done { print self.s; }

            var s: string& = new string;
        };

    .. spicy-output:: unit-params-string.spicy
        :exec: printf '\x2a' | spicy-driver -d %INPUT
        :show-with: foo.spicy

.. **

.. note::

    While this lack of support for ``inout`` may seem like a
    surprising restriction at first, it follows from Spicy's safety
    guarantees: since a subunit may access its parameters during its
    entire lifetime, generally Spicy couldn't guarantee that a
    parameter passed as ``inout`` at initialization time would
    actually remain around for modification the whole time. References
    do not have that problem: their wrapped values are guaranteed to
    remain valid as long as necessary. (Units happen to share that
    behaviour, too, which is why Spicy can support ``inout`` for
    them.)

.. _unit_attributes:

Unit Attributes
===============

Unit types support the following type attributes:

``&byte-order=ORDER``
    Specifies a byte order to use for parsing the unit where ``ORDER`` is of
    type :ref:`spicy_ByteOrder`. This overrides the byte order specified for the
    module. Individual fields can override this value by specifying their own
    byte-order. Example:

    .. spicy-code::

        type Foo = unit {
            version: uint32;
        } &byte-order=spicy::ByteOrder::Little;

``&convert=EXPR``
    Replaces a unit instance with the result of the expression
    ``EXPR`` after parsing it from inside a parent unit. See
    :ref:`attribute_convert` for an example. ``EXPR`` has access to
    ``self`` to retrieves state from the unit.

``&requires=EXPR``
    Enforces post-conditions on the parsed unit. ``EXPR`` must be a boolean
    expression that will be evaluated after the parsing for the unit has
    finished, but before any hooks execute. More than one ``&requires``
    attributes may be specified. Example:

    .. spicy-code::

        type Foo = unit {
            a: int8;
            b: int8;
        } &requires=self.a==self.b;

   See the :ref:`section on parsing constraints <attribute_requires>` for more
   details.

``&size=N``
    Limits the unit's input to ``N`` bytes, which it must fully
    consume. Example:

    .. spicy-code::

        type Foo = unit {
            a: int8;
            b: bytes &eod;
        } &size=5;

    This expects 5 bytes of input when parsing an instance of ``Foo``.
    The unit will store the first byte into ``a``, and then fill ``b``
    with the remaining 4 bytes.

    The expression ``N`` has access to ``self`` as well as to the
    unit's parameters.

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

``%port = PORT_VALUE [&originator|&responder]``
    A :ref:`type_port` to associate this unit with, optionally
    including a direction to limit its use to the corresponding side.
    This property has no built-in effect, but host applications may
    make use of the information to decide which unit type to use for
    parsing a connection's payload.

``%skip = ( REGEXP | Null );``
    Specifies a pattern which should be skipped when encountered in the input
    stream in between parsing of unit fields. This overwrites a value set at
    the module level; use ``Null`` to reset the property, i.e., not skip
    anything.

``%skip-pre = ( REGEXP | Null );``
    Specifies a pattern which should be skipped when encountered in the input
    stream before parsing of a unit begins. This overwrites a value set at the
    module level; use ``Null`` to reset the property, i.e., not skip anything.

``%skip-post = ( REGEXP | Null );``
    Specifies a pattern which should be skipped when encountered in the input
    stream after parsing of a unit has finished. This overwrites a value set at
    the module level; use ``Null`` to reset the property, i.e., not skip
    anything.

.. _synchronize-at:

``%synchronize-at = EXPR;``
    Specifies a literal to synchronize on if the unit is used as a
    synchronization point during :ref:`error recovery <error_recovery>`.
    The literal is left in the input stream.

.. _synchronize-after:

``%synchronize-after = EXPR;``
    Specifies a literal to synchronize on if the unit is used as a
    synchronization point during :ref:`error recovery <error_recovery>`.
    The literal is consumed and will not be present in the input stream after
    successful synchronization.

Units support some further properties for other purposes, which we
introduce in the corresponding sections.

Parsing Types
=============

Several, but not all, of Spicy's :ref:`data types <types>` can be
parsed from binary data. In the following we summarize the types that
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
    :exec: printf '1234567890123456' | spicy-driver -d %INPUT
    :show-with: foo.spicy

.. _parse_bitfield:

Bitfield
^^^^^^^^

:ref:`Bitfields <type_bitfield>` parse an integer value of a given
size, and then make selected smaller bit ranges within that value
available individually through dedicated identifiers. For example, the
following unit parses 4 bytes as an ``uint32`` and then makes the
value of bit 0 available as ``f.x1``, bits 1 to 2 as ``f.x2``, and
bits 3 to 4 as ``f.x3``, respectively:

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
    :exec: printf '\01\02\03\04' | spicy-driver -d %INPUT
    :show-with: foo.spicy

Generally, a field ``bitfield(N)`` field is parsed like an
``uint<N>``. The field then supports dereferencing individual bit
ranges through their labels. The corresponding expressions
(``self.x.<id>``) have the same ``uint<N>`` type as the parsed value
itself, with the value shifted to the right so that the least significant
extracted bit becomes the least significant bit of the returned value. As you can see in
the example, the type of the field itself becomes a tuple composed of
the values of the individual bit ranges.

By default, a bitfield assumes the underlying integer comes in network
byte order. You can specify a ``&byte-order`` attribute to change that
(e.g., ``bitfield(32) { ... } &byte-order=spicy::ByteOrder::Little``).

When parsing a ``bitfield(16)`` in network byte order and with bit order
``spicy::BitOrder::LSB0`` (default value of ``&bit-order``), bits are
numbered 0 to 15 from right to left.

.. code::

    MSB                           LSB
          <--   1         <--       0
    6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
    +---------------+---------------+
    |               |               |
    +-------------------------------+


This default bit numbering may be surprising given that some RFCs use the inverse
as documented in `RFC 1700 <https://www.rfc-editor.org/rfc/rfc1700.html>`_.
Here, the most significant bit is numbered 0 on the left with higher
bit numbers representing less significant bits to the right.
Concrete examples would be the `WebSocket framing <https://datatracker.ietf.org/doc/html/rfc6455#section-5.2>`_
or `IPv4 header <https://datatracker.ietf.org/doc/html/rfc791#section-3.1>`_
notations.

.. code::

    MSB                           LSB
    0       -->         1    -->
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
    +-+-+-+-+-------+-+-------------+
    |F|R|R|R| opcode|M| Payload len |
    |I|S|S|S|  (4)  |A|     (7)     |
    |N|V|V|V|       |S|             |
    | |1|2|3|       |K|             |
    +-+-+-+-+-------+-+-------------+

To express such bitfields more naturally in Spicy, use ``&bit-order=spicy::BitOrder::MSB0``
on the whole bitfield:

.. spicy-code:: parse-websocket-bitfield.spicy

    module WebSocket;

    import spicy;

    public type Header= unit {
        : bitfield(32) {
            fin: 0;
            rsv: 1..3;
            opcode: 4..7;
            mask: 8;
            payload_len: 9..15;
        } &bit-order=spicy::BitOrder::MSB0;
    };

The way to think about this is that the most significant bit of an integer in
network byte order is always the most left bit and the least significant bit
the most right one. Specifying the bit order as ``LSB0`` or ``MSB0`` essentially
sets the bit numbering direction by specifying the location of bit 0.

With little endian byte order, the bits are numbered zigzag-wise and
``MSB0`` and ``LSB0`` can again be used to change the direction of the bit
numbering. The following example uses ``spicy::ByteOrder::Little`` and
the default ``LSB0`` bit order for ``bitfield(16)``. Notice how the most
significant and least significant bit for a 2 byte little endian integer
are next to each other.

.. code::

    f: bitfield(16) {

      ...

    } &byte-order=spicy::ByteOrder::Little;

                  LSB MSB
         <--        0     <--   1
      7 6 5 4 3 2 1 0 5 4 3 2 1 0 9 8
    +---------------+---------------+
    |               |               |
    +-------------------------------+

With ``MSB0`` as bit order, the bit numbering direction is from left to right, instead:

.. code::

    f: bitfield(16) {

      ...

    } &byte-order=spicy::ByteOrder::Little &bit-order=spicy::BitOrder::MSB0;

                LSB MSB
        1  -->      0    -->
    8 9 0 1 2 3 4 5 0 1 2 3 4 5 6 7
    +---------------+---------------+
    |               |               |
    +-------------------------------+


Bit numbering with larger sized bitfields in little endian gets only more
confusing. Prefer network byte ordered bitfields unless it makes sense given
the spec you're working with.

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
    :exec: printf '\x21' | spicy-driver -d %INPUT
    :show-with: foo.spicy

When parsing a bitfield, you can enforce expected values for some
or all of the bitranges through an assignment-style syntax:

.. spicy-code::

    type Foo = unit {
        f: bitfield(8) {
            x1: 0..3 = 2;
            x2: 4..5;
            x3: 6..7 = 3;
        }
    };

Now parsing will fail if values of ``x1`` and ``x3`` aren't ``2`` and
``3``, respectively. Internally, Spicy treats bitfields with such
expected values similar to constants of other types, meaning they
operate as valid look-ahead symbols as well (see
:ref:`parse_lookahead`).

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
    included into the resulting value, but consumed.

``&until-including=DELIM``
    Similar to ``&until``, but this does include the delimiter
    ``DELIM`` into the resulting value.

At least one of these attributes must be provided.

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

When parsing a field through a :ref:`type_regexp`, the expression is
expected to match at the current position of the input stream. The
field's type becomes ``bytes``, and it will store the matching data.

Inside hooks for fields with regular expressions, you can access
capture groups through ``$1``, ``$2``, ``$3``, etc. For example:

.. spicy-code::

    x : /(a.c)(de*f)(h.j)/ {
        print $1, $2, $3;
        }

This will print out the relevant pieces of the data matching the
corresponding set of parentheses. (There's no ``$0``, just use ``$$``
as normal to get the full match.)

Matching an regular expression is more expensive if you need it to
capture groups. If are using groups inside your expression but don't
need the actual captures, add ``&nosub`` to the field to remove that
overhead.

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
    :exec: printf '\01\02' | spicy-driver -d %INPUT
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

    NAME : ELEM_TYPE[SIZE]

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
    :exec: printf '\01\02\03\04\05' | spicy-driver -d %INPUT
    :show-with: foo.spicy

It is possible to skip the ``SIZE`` (e.g., ``x: uint8[]``) and instead
use another kind of end conditions to terminate a vector's parsing
loop. To that end, vectors support the following attributes:

``&eod``
    Parses elements until the end of the input stream is reached.

``&size=N``
    Parses the vector from the subsequent ``N`` bytes of input data.
    This effectively limits the available input to the corresponding
    window, letting the vector parse elements until it runs out of
    data. (This attribute :ref:`works for fields of all types
    <attribute_size>`. We list it here because it's particularly
    common to use it with vectors.)

``&until=EXPR``
    Vector elements are parsed in a loop with ``EXPR`` being evaluated
    as a boolean expression after each parsed element, and before
    adding the element to the vector. Once ``EXPR`` evaluates to true,
    parsing stops *without* adding the element that was just
    parsed. Inside ``EXPR``, ``$$`` refers to the element most recently
    parsed.

``&until-including=EXPR``
    Similar to ``&until``, but does include the final element ``EXPR``
    into the field's vector when stopping parsing. Inside ``EXPR``,
    ``$$`` refers to the element most recently parsed.

``&while=EXPR``
    Continues parsing as long as the boolean expression ``EXPR``
    evaluates to true. Inside ``EXPR``, ``$$`` refers to the element
    most recently parsed.

If neither a size nor an attribute is given, Spicy will attempt to use
:ref:`look-ahead parsing <parse_lookahead>` to determine the end of
the vector based on the next expected token. Depending on the unit's
field, this may not be possible, in which case Spicy will decline to
compile the unit.

The syntax shown above generally works for all element types,
including subunits (e.g., ``x: MyUnit[]``).

.. note::

    The ``x: (<T>)[]`` syntax is quite flexible. In fact, ``<T>`` is
    not limited to subunits, but allows for any standard field
    specification defining how to parse the vector elements. For
    example, ``x: (bytes &size=5)[];`` parses a vector of 5-character
    ``bytes`` instances.

.. _hook_foreach:

When parsing a vector, Spicy supports using a special kind of field
hook, ``foreach``, that executes for each parsed element individually.
Inside that hook, ``$$`` refers to the element's final value:

.. spicy-code:: parse-vector-foreach.spicy

    module Test;

    public type Foo = unit {
        x: uint8[5] foreach { print $$, self.x; }
    };

.. spicy-output:: parse-vector-foreach.spicy
    :exec: printf '\01\02\03\04\05' | spicy-driver -d %INPUT
    :show-with: foo.spicy

As you can see, when a ``foreach`` hook executes the element has not yet
been added to the vector. You may indeed use a ``stop`` statement
inside a ``foreach`` hook to abort the vector's parsing without adding
the current element anymore. See :ref:`unit_hooks` for more on hooks.

.. _parse_void:

Void
^^^^

The :ref:`type_void` type can be used as a placeholder in fields not
meant to consume any data. This can be useful in some situations, such
as providing a branch in :ref:`switch <parse_switch>` constructs to
that foregoes any parsing, or attaching a :ref:`&requires
<attribute_requires>` attribute to enforce a condition.

Fields of type ``void`` do not have any accessible value.

Controlling Parsing
===================

Spicy offers a few additional constructs inside a unit's declaration
for steering the parsing process. We discuss them in the following.

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
    :exec: printf '\01\02\03\04' | spicy-driver -d %INPUT; printf '\02\02\03\04' | spicy-driver -d %INPUT
    :show-with: foo.spicy

.. versionadded:: 1.12 Conditional blocks

If the same condition applies to multiple subsequent fields, they can
be grouped together into a single conditional block:

.. spicy-code:: parse-if-block.spicy

    module Test;

    public type Foo = unit {
        a: int8;

        if ( self.a == 1 ) {
            b: int8;
            c: int8;
        }; # note the trailing semicolon

        on %done { print self; }
    };


The syntax supports an optional ``else``-block as well:

.. spicy-code:: parse-if-block-with-else.spicy

    module Test;

    public type Foo = unit {
        a: int8;

        if ( self.a == 1 ) {
            b: int8;
        }
        else {
            c: int8;
        }; # note the trailing semicolon

        on %done { print self; }
    };


For repeated cases of conditional parsing where a single expression
evaluates to one of several values, unit :ref:`parse_switch`
statements might allow for more compact and easier to maintain code.

.. _parse_lookahead:

Look-Ahead
^^^^^^^^^^

Internally, Spicy builds an LR(1) grammar for each unit that it
parses, meaning that it can actually look *ahead* in the parsing
stream to determine how to process the current input location. Roughly
speaking, if (1) the current construct does not have a clear end
condition defined (such as a specific length), and (2) a specific value
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
    :exec: printf '\01\02\03EOD\04' | spicy-driver -d %INPUT
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
of several parsing alternatives. There are two variants of this, an
explicit branch and one driving by look-ahead:

.. rubric:: Branch by expression

The most basic form of switching by expression looks like this:

.. spicy-code::

    switch ( EXPR ) {
        VALUE_1 -> FIELD_1;
        VALUE_2 -> FIELD_2;
        ...
        VALUE_N -> FIELD_N;
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
    :exec: printf 'A\01' | spicy-driver -d %INPUT; printf 'B\01\02' | spicy-driver -d %INPUT
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
            -> a: b"A";
            -> b: b"B";
            -> c: b"C";
        };

        on %done { print self; }
    };

.. spicy-output:: parse-switch-lhead.spicy
    :exec: printf 'A' | spicy-driver -d %INPUT
    :show-with: foo.spicy

While this example is a bit contrived, the mechanism becomes powerful
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
            -> a: A;
            -> b: B;
        };

        on %done { print self; }
    };

.. spicy-output:: parse-switch-lhead-2.spicy
    :exec: printf 'A ' | spicy-driver -d %INPUT; printf '\377\377' | spicy-driver -d %INPUT
    :show-with: foo.spicy

.. rubric:: Switching Over Fields With Common Size

You can limit the input any field in a unit switch receives by attaching an
optional ``&size=EXPR`` attribute that specifies the number of raw bytes to
make available. This is analog to the :ref:`field size attribute <attribute_size>`
and especially useful to remove duplication when each case is subject to the
same constraint.

.. spicy-code:: parse-switch-size.spicy

    module Test;

    public type Foo = unit {
        tag: uint8;
        switch ( self.tag ) {
           1 -> b1: bytes &eod;
           2 -> b2: bytes &eod &convert=$$.lower();
        } &size=3;

        on %done { print self; }
    };

.. spicy-output:: parse-switch-size.spicy
   :exec: printf '\01ABC' | spicy-driver -d %INPUT; printf '\02ABC' | spicy-driver -d %INPUT
   :show-with: foo.spicy

.. _backtracking:

Backtracking
^^^^^^^^^^^^

Spicy supports a simple form of manual backtracking. If a field is
marked with ``&try``, a later call to the unit's ``backtrack()``
method anywhere down in the parse tree originating at that field will
immediately transfer control over to the field following the ``&try``.
When doing so, the data position inside the input stream will be reset
to where it was when the ``&try`` field started its processing. Units
along the original path will be left in whatever state they were at
the time ``backtrack()`` executed (i.e., they will probably remain
just partially initialized). When ``backtrack()`` is called on a path
that involves multiple ``&try`` fields, control continues after the
most recent.

Example:

.. spicy-code:: parse-backtrack.spicy

    module Test;

    public type test = unit {
        foo: Foo &try;
        bar: Bar;

        on %done { print self; }
    };

    type Foo = unit {
        a: int8 {
            if ( $$ != 1 )
                self.backtrack();
           }
        b: int8;
    };

    type Bar = unit {
        a: int8;
        b: int8;
    };


.. spicy-output:: parse-backtrack.spicy
    :exec: printf '\001\002\003\004' | spicy-driver -d %INPUT; printf '\003\004' | spicy-driver -d %INPUT
    :show-with: backtrack.spicy

``backtrack()`` can be called from inside :ref:`%error hooks
<on_error>`, so this provides a simple form of error recovery
as well.

.. note::

    This mechanism is preliminary and will probably see refinement
    over time, both in terms of more automated backtracking and by
    providing better control where to continue after backtracking.

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
    :exec: printf '\x01\x02\x03\04' | spicy-driver -d %INPUT
    :show-with: foo.spicy

For ``&parse-at``, ``EXPR`` must yield an iterator pointing to (a
still valid) position of the current unit's input stream (such as
retrieved through :spicy:method:`unit::input`). The field will then be
parsed from the data starting at that location.

.. _random_access:

.. rubric:: Random access

While a unit is being parsed, you may revert the current input
position backwards to any location between the first byte the unit has
seen and the current position. You can use a set of built-in unit methods to
control the current position:

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

:spicy:method:`unit::position`
    Returns iterator to the current input position in the stream fed
    into this unit.

You can achieve random access by saving an iterator from ``input()``
in a unit variable, then later return to that position (or one derived
from it) by calling ``set_input()`` with that variable. Here's an
example that parses input data twice with different sub units:

.. spicy-code:: parse-random-access.spicy

    module Test;

    public type Foo = unit {
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
    :exec: printf '\00\00\00\01' | spicy-driver -d %INPUT
    :show-with: foo.spicy

If you look at output, you see that ``start`` iterator remembers its
offset, relative to the global input stream. It would also show the
data at that offset if the parser had not already discarded that at
the time we print it out.

.. note::

   Spicy parsers discard input data as quickly as possible as parsing
   moves through the input stream. Indeed, that's why using random
   access may come with a performance penalty as the parser now needs
   to buffer all of unit's data until it has been fully processed.

.. _filters:

Filters
=======

Spicy supports attaching *filters* to units that get to preprocess and
transform a unit's input before its parser gets to see it. A typical
use case for this is stripping off a data encoding, such as
compression or Base64.

A filter is itself just a ``unit`` that comes with an additional property
``%filter`` marking it as such. The filter unit's input represents the
original input to be transformed. The filter calls an internally
provided unit method :spicy:method:`unit::forward` to pass any
transformed data on to the main unit that it's attached to. The filter
can call ``forward`` arbitrarily many times, each time forwarding a
subsequent chunk of input. To attach a filter to a unit, one calls the
method :spicy:method:`unit::connect_filter` with an instance of the
filter's type. Putting that all together, this is an example of a simple
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
    :exec: printf 'aBcDe' | spicy-driver -d %INPUT
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
sink is the connector here that links two unit instances: one side
writing and one side reading, like a Unix pipe. As additional
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
    :exec: printf '\13GET /a/b/c\n' | spicy-driver -d -p Test::A %INPUT
    :show-with: foo.spicy

Let's see what's going on here. First, there's ``sink b`` inside the
declaration of ``A``. That's the connector, kept as state inside
``A``. When parsing for ``A`` is about to begin, the ``%init`` hook
connects the sink to a :ref:`new instance <operator_new>` of ``B``; that'll be the receiver
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

.. note::

   Because sinks are meant to decouple processing between two units, a
   unit connected to a sink will *not* pass any parse errors back up
   to the sink's parent. If you want to catch them, install an
   :ref:`%error <on_error>` hook inside the connected unit.

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
connect any that match their argument (if that's multiple, all will be
connected and all will receive the same data).

"MIME type" can mean actual MIME types, such ``text/html``.
Applications can, however, also define their own notion of
``<type>/<subtype>`` to model other semantics. For example, one could
use ``x-port/443`` as convention to trigger parsers by well-known
port. An SSL unit would then declare ``%mime-type = "x-port/443``, and
the connection would be established through the equivalent of
``connect_mime_type("x-port/%d" % resp_port_of_connection)``.

.. todo::

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


.. _unit_context:

Contexts
========

Parsing may need to retain state beyond any specific unit's lifetime.
For example, a UDP protocol may want to remember information across
individual packets (and hence units), or a bi-directional protocol may
need to correlate the request side with the response side. One option
for implementing this in Spicy is managing such state manually in
:ref:`global variables <variables>`, for example by maintaining a
global map that ties a unique connection ID to the information that
needs to be retained. However, doing so is clearly cumbersome and
error prone. As an alternative, a unit can make use of a dedicated
*context* value, which is an instance of a custom type that has its
lifetime determined by the host application running the parser. For
example, Zeek will tie the context to the underlying connection.

Any public unit can declare a context through a unit-level property
called ``%context``, which takes an arbitrary type as its argument.
For example:

.. spicy-code::

    public type Foo = unit {
        %context = bytes;
        [...]
    };

When used as a top-level entry point to parsing, the unit will then,
by default, receive a unique context value of that type. That context
value can be accessed through the :spicy:method:`unit::context`
method, which will return a :ref:`reference <type_reference>` to it:

.. spicy-code:: context-empty.spicy

    module Test;

    public type Foo = unit {
        %context = int64;

        on %init { print self.context(); }
    };

.. spicy-output:: context-empty.spicy
    :exec: spicy-driver -d %INPUT </dev/null
    :show-with: foo.spicy

By itself, this is not very useful. However, host applications can
control how contexts are maintained, and they may assign the same
context value to multiple units. For example, when parsing a protocol,
the :zeek:`Zeek integration <devel/spicy/index.html>` always creates a single context
value shared by all top-level units belonging to the same connection,
enabling parsers to maintain bi-directional, per-connection state.
The batch mode of :ref:`spicy-driver <spicy-driver>` does the same.

.. note::

    A unit's context value gets set only when a host application uses
    it as the top-level starting point for parsing. If in the above
    example `Foo` wasn't the entry point, but used inside another unit
    further down during the parsing process, its context would remain
    unset.

As an example, the following grammar---mimicking a request/reply-style
protocol---maintains a queue of outstanding textual commands to then
associate numerical result codes with them as the responses come in:

.. spicy-code:: context-pipelining.spicy

    module Test;

    # We wrap the state into a tuple to make it easy to add more attributes if needed later.
    type Pending = tuple<pending: vector<bytes>>;

    public type Requests = unit {
        %context = Pending;

        : Request[] foreach { self.context().pending.push_back($$.cmd); }
    };

    public type Replies = unit {
        %context = Pending;

        : Reply[] foreach {
            if ( |self.context().pending| ) {
                print "%s -> %s" % (self.context().pending.back(), $$.response);
                self.context().pending.pop_back();
            }
            else
                print "<missing request> -> %s", $$.response;
          }
    };

    type Request = unit {
        cmd: /[A-Za-z]+/;
        : b"\n";
    };

    type Reply = unit {
        response: /[0-9]+/;
        : b"\n";
    };

.. spicy-output:: context-pipelining.spicy
    :exec: spicy-driver -F programming/examples/context-input.dat %INPUT
    :show-as: spicy-driver -F input.dat context.spicy

The output is produced from :download:`this input batch file
<examples/context-input.dat>`. This would work the same when used with
the Zeek on a corresponding packet trace.

Note that the units for the two sides of the connection need to
declare the same ``%context`` type. Processing will abort at
runtime with a type mismatch error if that's not the case.

.. _error_handling:

Error Handling
===============

Whenever a parser encounters an unexpected situation during
processing, it triggers a runtime error. This includes parsing errors
due to input that does not match the current unit, failing
:ref:`&requires <attribute_requires>` conditions, and also any logic
errors in hooks, such as attempting to read an unset unit field or
accessing an invalid vector index.

By default, any runtime error will cause the parsing to terminate
immediately, with a corresponding error message reported back to the
host application. The Spicy parser will not be able to continue
processing afterwards. However, there are a couple of ways to catch
*parsing errors* (but not other runtime errors) and potentially
recover from them, which we discuss in the following.

.. _parsing_errors:

A unit can provide special :ref:`%error hooks <unit_hooks>` that will
execute when a parsing error is encountered. A unit-wide ``%error``
hook will catch all parsing errors occurring anywhere inside the unit,
including any sub-units (if not otherwise handled by the sub-unit
itself already). Example:

.. code-block:: spicy

    module MyModule;

    type MyType = unit {
        magic: b"MAGIC";

        on %error(msg: string) {
            print "Error when parsing MyUnit: ", msg;
        }
    };

The ``msg`` parameter is optional. If it's specified, it will contain
an error message describing the issue.

By default, even with an ``%error`` hook in place, the parser will
still terminate after executing the hook. To change that, the hook may
use :ref:`backtracking` to specify where to continue parsing after the
error. Alternatively, if :ref:`automatic error recovery
<error_recovery>` is in place, the parser will attempt recovery after
the error hooks have executed.

.. versionadded:: 1.12 Per-field ``%error`` handler

Rather than defining a unit-wide ``%error`` hook, it is also possible
to just have an individual field catch its own parsing errors. The
easiest way to do this is to attach an ``%error`` attribute to an
inline hook:

.. code-block:: spicy

    module My;

    type MyType = unit {
        magic: b"MAGIC" %error { # will run if magic cannot be parsed
            print "magic not found";
        }
    };

To get access to the error message as well, define it out of line like this:

.. code-block:: spicy

    module MyUnit;

    type MyType = unit {
        magic: b"MAGIC"

        on magic(msg: string) %error {
            print "Error when parsing magic: ", msg;
        }
    };


.. _error_recovery:

Error Recovery
==============

Real world input does not always look like what parsers expect:
endpoints may not conform to the protocol's specification, a parser's
grammar might not fully cover all of the protocol, or some input may
be missing due to packet loss or stepping into the middle of a
conversation. By default, if a Spicy parser encounters such
situations, it will abort parsing altogether and issue an error
message. Alternatively, however, Spicy allows grammar writers to
specify heuristics to recover from errors. The main challenge here is
finding a spot in the subsequent input where parsing can reliably
resume.

Spicy employs a two-phase approach to such recovery: it first searches
for a possible point in the input stream where it seems promising to
attempt to resume parsing; and then it confirms that choice by trying
to parse a few fields at that location according to the grammar
grammar to see if that's successful. We say that during the first part
of this process, the Spicy parser is in *synchronization mode*; d
during the second, it is in *trial mode*.

.. rubric:: Phase 1: Synchronization

To identity locations where parsing can attempt to pick up again after
an error, a grammar can add ``&synchronize`` attributes to selected unit
fields, marking them as a *synchronization points*. Whenever an error
occurs during parsing, Spicy will determine the closest
synchronization point in the grammar following the error's location,
and then attempt to continue processing there by skipping ahead in the
input data until it aligns with what that field is looking for.

A synchronization point may be any of the following:

- A field for which parsing begins with a constant literal (e.g., a specific
  sequence of bytes). To realign the input stream, the parser will search the
  input for the next occurrence of this literal, discarding any data in
  between. Example::

    type X = unit { ... }

    type Y = unit {
        a: b"begin-of-Y";
        b: bytes &size=10;
    };

    type Foo = unit {
        x: X;
        y: Y &synchronize;
    };

  If parse error occurs during ``Foo::x``, Spicy will move ahead to ``Foo::y``,
  switch into synchronization mode, and start search the input for the bytes
  ``begin-of-Y``. If found, it'll continue with parsing ``Foo::y`` at that location
  in trial mode (see below).

  .. note::

    Behind the scenes, synchronization through literals uses the same machinery
    as :ref:`look-ahead parsing <parse_lookahead>`, meaning that it works
    across sub-units, vector content, ``switch`` statements, etc.. No matter how
    complex the field, as long as there's one or more literals that always
    *must* be coming first when parsing it, the field may be used as a
    synchronization point.

- A field with a type which specifies :ref:`%synchronize-at <synchronize-at>`
  or  :ref:`%synchronize-after <synchronize-after>`. The parser will search the
  input for the next occurrence of the given literal, discarding any data in
  between. If the search was successful, ``%synchronize-at`` will leave the
  input at the position of the search literal for later extraction while
  ``%synchronize-after`` will discard the search literal.

  If either of these unit properties is specified, it will always overrule any
  other potential synchronization points in the unit. Example::

    type X = unit {
        ...
        : /END/;
    };

    type Y = unit {
        %synchronize-after = /END/;
        a: bytes &size=10;
    };

    type Foo = unit {
        x: X;
        y: Y &synchronize;
    };

- A field that's located inside the input stream at a fixed offset relative to
  the field triggering the error. The parser will then be able to skip ahead to
  that offset. Example::

    type X = unit { ... }
    type Y = unit { ... }

    type Foo = unit {}
        x: X &size=512;
        y: Y &synchronize;
    };

  Here, when parsing ``Foo:x`` triggers an error, Spicy will know that it can
  continue with ``Foo::y`` at offset ``<beginning of Foox:x> + 512``.

  .. todo::

    This synchronization strategy is not yet implemented.

- When :ref:`parsing a vector <parse_vector>`, the inner elements may provide
  synchronization points as well. Example::

     type X = unit {
         a: b"begin-of-X";
         b: bytes &size=10;
     };

     type Foo = unit {}
         xs: (X &synchronize)[];
     };

  If one element of the vector ``Foo::xs`` fails to parse, Spicy will attempt
  to find the beginning of the next ``X`` in the input stream and continue
  there. For this to work, the vector's elements must itself represent valid
  synchronization point (e.g., start with a literal). If the list is of fixed
  size, after successful synchronization, it will contain the expected number
  of entries, but some of them may remain (fully or partially) uninitialized
  if they encountered errors.

.. rubric:: Phase 2: Trial parsing

Once input has been realigned with a synchronization point, parsing
switches from synchronization mode into trial mode, in which the
parser will attempt to confirm that it has indeed found a viable place
to continue. It does so by proceeding to parse subsequent input from
the synchronization point onwards, until one of the following occurs:

- A unit hook explicitly acknowledges that synchronization has been successful
  by executing Spicy's :ref:`statement_confirm` statement. Typically, a grammar
  will do so once it has been able to correctly parse a few fields following
  the synchronization point--whatever it needs to sufficiently certain that
  it's indeed seeing the expected structure.

- A unit hook explicitly declines the synchronization by executing Spicy's
  :ref:`statement_reject` statement. This will abandon the current
  synchronization attempt, and switch back into the original synchronization
  mode again to find another location to try.

- Parsing reaches the end of the grammar without either ``confirm`` or
  ``reject`` already called. In this case, the parser will abort with a fatal
  parse error.

Note that during trial mode, any fields between the synchronization point and
the eventual ``confirm``/``reject`` location will already be processed as
usual, including any hooks executing except ``%error``. This may leave the
unit's state in a partially initialized state if trial parsing eventually
fails. Trial mode will also consume any input along the way, with any further
synchronization attempts proceeding only on subsequent, not yet seen, data.

.. _error_recovery_hooks:

.. rubric:: Synchronisation Hooks

For customization, Spicy provides a set of hooks executing at
different points during the synchronization process:

``on %synced { ...}``
    Executes when a synchronization point has been found and parsing
    resumes there, just before the parser begins processing the
    corresponding field in trial mode.

``on %confirmed { ...}``
    Executes when trial mode ends successfully with :ref:`statement_confirm`.

``on %rejected { ...}``
    Executes when trial mode fails with :ref:`statement_reject`.

``on %sync_advance(offset: uint64)``
    Executes regularly (see below) while the parser is searching for a
    synchronization point. The `offset` is given the current position
    inside the input stream.

    This hook can be used check if the parser is skipping too much
    data for the analysis to remain useful. For example, a protocol
    analyzer could decide to bail out if the input stream consists
    mainly of gaps, as reported by
    :spicy:method:`self.stream().statistics() <stream::statistics>`.

    By default, the hook executes every 4KB of input data skipped
    while searching for a synchronization point. It may not
    necessarily trigger immediately at the 4KB mark, but soon after
    when parsing gets a chance to check the input stream's position.

    You may change the trigger volume by defining a unit property
    ``%sync-advance-block-size = <VALUE>`` where ``<VALUE>`` is an
    alternative  size value in bytes. As usual, this property can also
    be set at the module level to apply to all units.

.. rubric:: Example Synchronization Process

As an example, let's consider a grammar consisting of two sections
where each section is started with a section header literal (``SEC_A``
and ``SEC_B`` here).

We want to allow for inputs which miss parts or all of the first
section. For such inputs, we can still synchronize the input stream by
looking for the start of the second section. (For simplicity, we just
use a single unit, even though typically one would probably have
separate units for the two sections.)

.. spicy-code:: parse-synchronized.spicy

    module Test;

    public type Example = unit {
        start_a: /SEC_A/;
        a: uint8;

        # If we fail to find e.g., 'SEC_A' in the input, try to synchronize on this literal.
        start_b: /SEC_B/ &synchronize;
        b: bytes &eod;

        # In this example confirm unconditionally.
        on %synced {
            print "Synced: %s" % self;
            confirm;
        }

        # Perform logging for these %confirmed and %rejected.
        on %confirmed { print "Confirmed: %s" % self; }
        on %rejected { print "Rejected: %s" % self; }

        on %done { print "Done %s" % self; }
    };

Let us consider that this parsers encounters the input
``\xFFSEC_Babc`` that missed the ``SEC_A`` section marker:

- ``start_a`` missing,
- ``a=255``
- ``start_b=SEC_B`` as expected, and
- ``b=abc``.

For such an input parsing will encounter an initial error when it sees
``\xFF`` where ``SEC_A`` would have been expected.

1. Since ``start_b`` is marked as a synchronization point, the parser
   enters synchronisation mode, and jumps over the field ``a`` to
   ``start_b``, to now search for ``SEC_B``.

2. At this point the input still contains the unexpected ``\xFF`` and
   remains ``\xFFSEC_Babc`` . While searching for ``SEC_B`` ``\xFF``
   is skipped over, and then the expected token is found. The input
   is now ``SEC_Babc``.

3. The parser has successfully synchronized and enters trial mode. All
   ``%synced`` hooks are invoked.

4. The unit's ``%synced`` hook executes ``confirm`` and the parser
   leaves trial mode. All ``%confirmed`` hooks are invoked.

5. Regular parsing continues at ``start_b``. The input was ``SEC_Babc`` so
   ``start_b`` is set to ``SEC_B`` and ``b`` to ``abc``.

Since parsing for ``start_a`` was unsuccessful and ``a`` was jumped
over, their fields remain unset.

.. spicy-output:: parse-synchronized.spicy
   :exec: printf '\xFFSEC_Babc' | spicy-driver -d %INPUT
   :show-with: foo.spicy
