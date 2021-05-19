
.. _dev_debugging:

Debugging
=========

The user manual's :ref:`debugging section <debugging>` serves as a
good starting point for development-side debugging as well---it's
often the same mechanisms that help understand why something's not
working as expected. In particular, looking at the generated HILTI &
C++ code often shows quickly what's going on.

That section describes only runtime debugging output. The Spicy
toolchain also has a set of compile-time debug output streams that
shine light on various parts of the compiler's operation. To activate
that output, both ``spicyc`` and ``spicy-driver`` (and ``hiltic`` as
well) take a ``-D`` option accepting a comma-separated list of stream
tags. The following choices are available:

``ast-dump-iterations``
    The compiler internally rewrites ASTs in multiple rounds until
    they stabilize. Activating this stream will print the ASTs into
    files ``dbg.*`` on disk after each round. This is pretty noisy,
    and maybe most helpful as a last resort when it's otherwise hard
    to understand some aspects of AST processing without seeing really
    *all* the changes.

``ast-final``
    Prints out all the final ASTs, with all transformations, ID &
    operator resolving, etc fully applied (and just *before* final
    validation).

``ast-orig``
    Prints out all the original ASTs, before any changes are
    applied.

``ast-pre-transformed``
    Prints out ASTs just before the AST transformation passes kick in.
    Note that "transformation" here refers to a specific pass in the
    pipeline that's primarily used for Spicy-to-HILTI AST rewriting.

``ast-resolved``
    Prints out ASTs just after the pass that resolves IDs and operators has
    concluded. Note that this happens once per round, with
    progressively more nodes being resolved.

``ast-scopes``
    Prints out ASTs just after scopes have been built for all nodes,
    with the output including the scopes. Note that this happens
    once per round, with progressively more nodes being resolved.

``ast-transformed``
    Prints out ASTs just after the AST transformation passes kick in.
    Note that "transformation" here refers to a specific pass in the
    pipeline that's primarily used for Spicy-to-HILTI AST rewriting.

``ast-codegen``
    Prints out the ASTs used for C++ code generation. These are the final ASTs
    with possibly additional global optimizations applied to them.

``compiler``
    Prints out a various progress updates about the compiler's
    internal workings. Note that ``driver`` is often a better
    high-level starting point.

``driver``
    Prints out the main high-level steps while going from source code
    to final compiler output. This stream provides a good high-level
    overview what's going on, with others going into more detail on
    specific parts.

``grammar``
    Prints out the parsing grammars that Spicy's parser generator
    creates before code generation.

``jit``
    Prints out details about the JIT process.

``parser``
    Prints out details about flex/bison processing.

``resolver``
    Prints out a detailed record of how, and why, IDs and operators
    are resolved (or not) during AST rewriting.
