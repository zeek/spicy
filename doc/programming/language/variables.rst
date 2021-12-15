
.. _variables:

=======================
Variables and Constants
=======================

At the global module level, we declare variables with the ``global``
keyword::

    [public] global NAME: TYPE [= DEFAULT];

This defines a global variable called ``NAME`` with type ``TYPE``. If the
variable is declared with ``public`` visibility other modules can reference it.
If a default is given, Spicy initializes the global accordingly before any
code executes. Otherwise, the global receives a type-specific default,
typically the type's notion of a null value. As a result, globals are always
initialized to a well-defined value.

As a shortcut, you can skip ``: TYPE`` if the global comes with a
default. Spicy then just applies the expression's type to the global.

We define global constants in a similar way, just replacing ``global``
with ``const``:

.. spicy-code::

    const x: uint32 = 42;
    const foo = "Foo";

Inside a function, local variables use the same syntax once more, just
prefixed with ``local`` this time:

.. spicy-code::

    function f() {
        local x: bytes;
        local y = "Y";

    }

Usual scoping rules apply to locals. Just like globals, locals are
always initialized to a well-defined value: either their default if
given, or the type's null value.
