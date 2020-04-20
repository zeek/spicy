
.. _functions:

=========
Functions
=========

Spicy's language allows to define custom functions just
like most other languages. The generic syntax for defining a function
with is ``N`` parameters is::

    [public] function NAME(NAME_1: TYPE_1, ..., NAME_N: TYPE_N) [: RETURN_TYPE ] {
        ... BODY ...
    }

A ``public`` function will be :ref:`accessible from other modules
<modules>` . If the return type is skipped, it's implicitly taken as
``void``, i.e., the function will not return anything. If a function
has return type other than void, all paths through the body must end
in a :ref:`statement_return` returning a corresponding value.

A parameter specification can be postfixed with a default value:
``NAME: TYPE = DEFAULT``. Callers may then omit that parameter.

By default, by parameters are passed by constant reference and hence
remain read-only inside the function's body. To make a parameter
modifiable, with any changes becoming visible to the caller, a
parameter can be prefixed with ``inout``:

.. spicy-code:: function-inout.spicy

    module Test;

    global s = "1";

    function foo(inout x: string) {
        x = "2";
    }

    print s;
    foo(s);
    print s;

.. spicy-output:: function-inout.spicy
    :exec: spicyc -j %INPUT

Spicy has couple more function-like constructs (:ref:`unit_hooks` and
:ref:`unit_parameters`) that use the same conventions for parameter
passing.
