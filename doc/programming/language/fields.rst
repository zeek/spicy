
.. _field_declarations:

==================
Field Declarations
==================

You can predeclare unit fields at the global module level for later
reuse, creating macro-like shortcuts to common field specifications.

The general syntax for field declarations is::

    field NAME = FIELD_SPEC;

``FIELD_SPEC`` can be any right-hand side of a standard unit field,
excluding any unit parameters, sinks, and conditions. Once declared,
you can use ``NAME`` inside a unit field where normally the field type
would go. Here's a simple example::

    field Foo = bytes &size=5;

    type MyUnit = {
        x: Foo;
    };

This parses the field ``x`` as a ``bytes`` instance of 5 characters.
Similarly, the following would parse ``x`` through a regular
expression::

    field Foo = /Fo+Ba+r/;

As the ``bytes`` example shows, attributes will be preserved. This
allows for more complex scenarios. For example, the following
declaration hides an internal subunit through ``&convert``::

    type Bar = unit {
        data: /[0-9]+/;
    };

    field Foo = Bar &convert=$$.data.to_int();

    type MyUnit = {
        x: Foo;
    };

Here, the resulting type of ``x`` will be ``int64`` (i.e., the result
of the ``&convert`` expression).

You can also include hooks with field declarations. Let's extend the
``field`` declaration in the previous example like this::

    field Foo = Bar &convert=$.to_int() { print $$; }

Now the integer value will be printed out when ``x`` has been parsed.
