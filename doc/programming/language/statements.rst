
.. _statements:

======================
Statements & Operators
======================

Most of Spicy's language constructs are pretty standard stuff. We
summarize them briefly in the following. We include Spicy's statements
here, as well as some generic, non-trivial operators that aren't
type-specific (e.g.,  ``new``, ``begin``). For operators specific to a
type, see the type's documentation.

.. _statement_assert:

``assert``
----------

::

    assert EXPR;

    assert EXPR : MSG;

Ensures at runtime that ``EXPR`` evaluates to a ``True`` value. If it
doesn't, an exception gets thrown that will typically abort execution.
``EXPR`` must either be of boolean type to begin with, or support
coercion into it. If ``MSG`` is specified, it must be a string or
:ref:`error <type_error>`, and will be carried along with the
exception.

.. note::

    Technically, the version providing a ``MSG`` isn't a separate
    syntax but just leveraging the :ref:`condition test
    <operator_condition_test>` operator.

.. _statement_assert_exception:

``assert-exception``
--------------------

::

    assert-exception EXPR;

    assert-exception EXPR : MSG;

Ensures at runtime that evaluating ``EXPR`` triggers an exception. If
it indeed does, the exception is silently caught and execution
proceeds normally. If it doesn't, an ``AssertionFailure`` exception is
triggered by the statement, which will typically abort execution. If
``MSG`` is specified, it must be a string or :ref:`error
<type_error>`, and will be carried along with the exception.

.. _operator_begin:

``begin``
---------

.. include:: /autogen/types/generic-begin.rst

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

.. _statement_continue:

``continue``
------------

::

    continue;

Inside a :ref:`statement_for` or :ref:`statement_while` loop, ``continue``
causes the remaining portion of the enclosing loop body to be skipped.

.. _operator_end:

``end``
-------

.. include:: /autogen/types/generic-end.rst

.. _statement_export:

``export``
----------

::

    export TYPE_ID;

Prohibits the Spicy optimizer from applying certain aggressive
optimizations to the given type that might change its externally
visible properties, such as which fields are actually stored in the
type's values. See :ref:`optimization` for more.

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

    global v = vector("a", "b", "c");

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

.. _operator_new:

``new``
-------

.. include:: /autogen/types/generic-new.rst

.. _operator_pack:

``pack``
--------

.. include:: /autogen/types/generic-pack.rst

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


.. _operator_typeinfo:

``typeinfo``
------------

::

    typeinfo(TYPE)
    typeinfo(EXPR)

Returns a value of type :ref:`type <type_type>`, representing the
given type, or the type of the given expression, respectively.

.. _operator_unpack:

``unpack``
----------

.. include:: /autogen/types/generic-unpack.rst

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

.. _operator_condition_test:

``:`` (Condition Test)
----------------------

::

    COND : ERROR

The *condition test* operator expects a boolean value as ``COND`` on
the left-hand-side, and a value of type :ref:`error <type_error>` on
the right-hand-side. It returns a value of type ``result<void>`` that
will be set (i.e., evaluate to true) if ``COND`` is true; whereas it
will instead have its error set to the provided error value if
``COND`` is false.

Example:

::

    global x: result<void> = (4 == 5 : error"4 is not 5");
    assert !x; # x holds error result


``ERROR`` can also be given as a string, which will automatically be
converted to an ``error`` value. So this expression is equivalent to
the one above:

::

    4 == 5 : "4 is not 5"

Such condition tests are used with :ref:`assert <statement_assert>`
and :ref:`&requires <attribute_requires>`.
