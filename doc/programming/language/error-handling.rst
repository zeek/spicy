
.. _error_handling:

===============
Error Handling
===============

.. todo::

    Spicy's error handling remains quite limited at this point, with
    more to come here in the future.

.. _exceptions:

.. rubric:: Exceptions

Exceptions provide Spicy's primary mechanism for reporting errors.
Currently, various parts of the runtime system throw exceptions if
they encounter unexpected situations. In particular, the generated
parsers throw ``ParsingError`` exceptions if they find themselves
unable to comprehend their input. However, the support for catching
and handling exception is remains minimal at the moment. For now, only
``ParsingError`` exceptions can be caught indirectly through the
:ref:`%on_error <on_error>` unit hook, which internally is nothing
else than an exception handler.

.. todo::

    Support for catching other exception throughs :ref:`statement_try`
    needs to be added still (:issue:`89`).

.. rubric:: ``result<T>`` / ``error``

.. todo:: Spicy doesn't have ``result``/``error`` yet (:issue:`90`).

.. rubric:: Error recovery

Support for resynchronizing parser with their input stream after parse errors
is discussed in the section on :ref:`error recovery <error_recovery>`.
