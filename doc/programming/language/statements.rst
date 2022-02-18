
.. _statements:

==========
Statements
==========

Most of Spicy's statements are pretty standard stuff. We summarize
them briefly in the following.

.. _statement_assert:

``assert``
----------

::

    assert EXPR;

    assert EXPR : MSG;

Ensures at runtime that ``EXPR`` evaluates to a ``True`` value. If it
doesn't, an exception gets thrown that will typically abort execution.
``EXPR`` must either be of boolean type to begin with, or support
coercion into it. If ``MSG`` is specified, it must be a string and
will be carried along with the exception.

.. _statement_break:

``break``
---------

::

    break;

Inside a :ref:`statement_for` or :ref:`statement_while` loop,
``break`` aborts the loop's body, with execution then continuing
right after the loop construct.

.. _statement_confirm:

``confirm``
-----------

::

    confirm;

If the parser is currently in trial mode, confirm that the unit is successfully
synchronized to the input; the unit is then put into regular parsing mode
again. If the unit is not in trial mode ``confirm`` has no effect.

See :ref:`statement_reject` to reject the synchronization instead.

``confirm`` can only be invoked from hooks.

.. _statement_for:

``for``
-------

::

    for ( ID in ITERABLE )
        BLOCK

Loops over all the elements of an iterable value. ``ID`` is an
identifier that will become local variable inside ``BLOCK``, with the
current loop element assigned on each round. ``ITERABLE`` is a value
of any type that provides iterators.

Examples:

.. spicy-code:: statement-for.spicy

    module Test;

    for ( i in [1, 2, 3] )
        print i;

    for ( i in b"abc" ) {
        print i;
    }

    local v = vector("a", "b", "c");

    for ( i in v )
        print i;

.. spicy-output:: statement-for.spicy
    :show-with: for.spicy
    :exec: spicyc -j %INPUT

.. _statement_if:

``if``
------

::

    if ( EXPR )
        BLOCK

    if ( EXPR )
        BLOCK
    else
        BLOCK

A classic ``if``-statement branching based on a boolean expression
``EXPR``.

.. _statement_import:

``import``
----------

::

    import MODULE;

Makes the content of another module available, see :ref:`modules` for
more.

.. _statement_print:

``print``
---------

::

    print EXPR;

    print EXPR_1, ..., EXPR_N;

Prints one or more expressions to standard output. This is supported
for expressions of any type, with each type knowing how to render its
values into a readable representation. If multiple expressions are
specified, commas will separate them in the output.

.. note::

    A particular use-case combines ``print`` with string interpolation
    (i.e., :spicy:op:`string::Modulo`):

    .. spicy-code:: statement-interpolation.spicy

        module Test;

        print "Hello, %s!" % "World";
        print "%s=%d" % ("x", 1);

    .. spicy-output:: statement-interpolation.spicy
        :show-with: print.spicy
        :exec: spicyc -j %INPUT

.. _statement_reject:

``reject``
----------

::

    reject;

If the parse is currently in trial mode, reject the synchronization; this
immediately fails parsing of the unit and raises the parse error which caused
the unit to be put into trial mode. If the unit is not in trial mode this
triggers a generic parse error.

See :ref:`statement_confirm` to confirm the synchronization instead.

``reject`` can only be invoked from hooks.

.. _statement_return:

``return``
----------

::

    return;

    return EXPR;

Inside a function or hook, ``return`` yields control back to the
caller. If it's a function with a non-void return value, the
return must provide a corresponding ``EXPR``.

.. _statement_stop:

``stop``
--------

::

    stop;

Inside a ``foreach`` container hook (see :ref:`here <foreach>`), aborts
the parsing loop without adding the current (final) value to the
container.

.. _statement_switch:

``switch``
----------

::

    switch ( [local IDENT =] CTRL_EXPR ) {
        case EXPR [, ..., EXPR]:
            BLOCK;

        ...

        case EXPR [, ..., EXPR]:
            BLOCK;

       [default:
            BLOCK]
    }

.. _statement_throe:

Branches across a set of alternatives based on the value of an control
expression. ``CTRL_EXPR`` is compared against all the ``case``
expressions through the type's equality operator, coercing
``CTRL_EXPR`` accordingly first where necessary. If ``local IDENT`` is
specified, the blocks have access to a corresponding local variable
that holds the value of the control expression. If no ``default`` is
given, the runtime will throw an ``UnhandledSwitchCase`` exception if
there's no matching case.

.. note::

    Don't confuse the ``switch`` statement with the unit type's
    :ref:`switch parsing construct <parse_switch>`. They look similar,
    but do different things.

.. _statement_throw:

``throw``
---------

::

    throw EXPR;


Triggers a parse error exception with the message indicated by ``EXPR``. ``EXPR`` needs
to be a :ref:`type_string`. ``throw`` aborts parsing.

.. _statement_try:

``try/catch``
-------------

.. todo:: This isn't available in Spicy yet (:issue:`89`).

::

    try
        BLOCK

    catch [(TYPE IDENT)]
        BLOCK

    ...

    catch [(TYPE IDENT)]
        BLOCK

Catches any exception thrown in the ``try`` block that match one of
the types in any of ``catch`` headers, which must be
:ref:`type_exception` types. A ``catch`` without a type matches any
exception. If no ``catch`` matches an exception thrown in the ``try``
block, it'll be propagated further up the stack. A bare ``throw``
statement can be used inside a ``catch`` block to rethrow the current
exception.

.. _statement_while:

``while``
---------

::

    while ( COND )
        BLOCK

    while ( local IDENT = EXPR; COND )
        BLOCK

``while`` introduces a loop that executes ``BLOCK`` for as long as the
boolean ``COND`` evaluates to true. The second form initializes a new
local variable ``IDENT`` with ``EXPR``, and makes it available inside
both ``COND`` and ``BLOCK``.
