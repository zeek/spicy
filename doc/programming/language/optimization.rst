
.. _optimization:

============
Optimization
============

Behind the scenes, the Spicy compiler applies a number of optimization
techniques to the generated code to improve its performance based on
the Spicy features that a parser uses (or doesn't use). Most of these
optimizations do not change the semantics of the parser and hence
remain transparent to the user. However, the compiler also supports a
set of more aggressive optimizations that may affect the externally
visible behavior of the parser. These advanced optimizations are
enabled by default but can be disabled by passing
``--strict-public-api`` to :ref:`spicyc` or :ref:`spicy-driver` on the
command line. When producing debug code with ``--debug``, aggressive
optimizations are disabled automatically to avoid surprising behavior
during development. To enable them even in debug mode, add
``--no-strict-public-api`` to the command line.

The two main effects of these more aggressive optimizations are:

- When printing Spicy values through ``print`` (or other mechanisms
  that render values into string representations), some fields may be
  shown as ``(optimized out)`` with their values omitted. This means
  the optimizer decided to skip storing these fields because none of
  the compiled Spicy code uses them in a way that would affect the
  parser's behavior other than for display purposes.

  .. note::

        When developing a new parser, it's common to print out
        ``unit`` values to get a quick look at the data being parsed.
        Since seeing lots of ``(optimized out)`` isn't very helpful
        in that case, we recommend running the compiler with
        ``--debug`` during development, which (as mentioned above) disables
        the more aggressive optimizations by default.

        Note that printing individual fields directly (e.g.,
        ``print foo.y``) will always show their values, since the
        field is now actually being used, which prevents the optimizer
        from eliding it.

- The compiler is free to change the public C++ API of the generated
  parser. This includes omitting parsed fields that aren't needed for
  the parser to function correctly, and changing the signatures of
  public functions. As a result, host applications cannot rely on
  static properties of the generated code but must instead use the
  :ref:`generic runtime API <host_applications_generic>` to interact
  with parsers. Any information returned by the runtime introspection
  functions is guaranteed to be correct and match the generated code.

In addition to wholesale activation/deactivation of these aggressive
optimizations, there are a couple of ways to control them more
fine-grained from within Spicy source code:

- To explicitly prohibit any externally visible changes to a specific
  Spicy type, export it through ``export TYPE_ID;``.

- To prevent an individual ``unit`` or ``struct`` field from being
  optimized out, add the ``&always-emit`` attribute to it.
