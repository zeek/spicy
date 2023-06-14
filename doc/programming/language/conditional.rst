
.. _conditional_compilation:

=======================
Conditional Compilation
=======================

Spicy scripts offer a basic form of conditional compilation through
``@if``/``@else``/``@endif`` blocks, similar to a C preprocessor. For
now, this supports only a couple types of conditions that are useful
for feature and version testing. For example, the following
``@if``/``@else`` block branches to different code based on the Spicy
version:

.. spicy-code::

    @if SPICY_VERSION < 10401
        <code for Spicy versions older than 1.4.1>
    @else
        <code for Spicy versions equal or newer than 1.4.1>
    @endif


``@if`` directives can take one of the following forms:

    ``@if [!] IDENTIFIER OPERATOR VALUE``
        Compares the value of ``IDENTIFIER`` against ``VALUE``.
        Supported comparison operators are ``==``, ``!=``, ``<``,
        ``<=``, ``>``, ``>=``. See below for valid identifiers. If an
        identifier is not defined, its value is assumed to be
        zero.

    ``@if [!] IDENTIFIER``
        This is a shortcut for ``@if [!] IDENTIFIER != 0``.

By default, Spicy currently provides just one pre-defined identifier:

    ``SPICY_VERSION``
        The current Spicy version in numerical format (e.g., 10000 for
        version 1.0; see the output of ``spicy-config --version-number``).

Zeek defines a couple of :ref:`additional
identifiers <zeek_conditional_compilation>`.
