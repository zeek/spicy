
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

``ast-codegen``
    Prints out the AST used for C++ code generation. These is the final AST
    with possibly additional global optimizations applied to them.

``ast-declarations``
    Prints out all declaration nodes once AST is fully resolved (same
    time as `ast-final`).

``ast-dump-iterations``
    The compiler internally rewrites the AST in multiple rounds until
    it stabilizes. Activating this stream will print the AST into
    files ``dbg.*`` on disk after each round. This is pretty noisy,
    and maybe most helpful as a last resort when it's otherwise hard
    to understand some aspects of AST processing without seeing really
    *all* the changes.

``ast-final``
    Prints out all the final AST after resolving has finished, with
    all transformations, ID & operator resolving, etc fully applied
    (and just *before* final validation). Note the optimizer will not
    have run yet, use `ast-codegen` to get the *really* final AST.

``ast-orig``
    Prints out the original AST, before any changes are applied.

``ast-resolved``
    Prints out AST just after the pass that resolves all the AST's
    nodes has concluded. has concluded. Note that this happens once
    per round, with progressively more nodes being resolved. Use
    `ast-final` to just see the end result.

``ast-stats``
    Prints out various statistics about the AST after resolving once
    the AST is fully resolved (same time as `ast-final`).

``ast-transformed``
    Prints out AST just after the AST transformation pass has
    completed,"transformation" here refers to a specific pass in the
    pipeline that's primarily for Spicy-to-HILTI AST rewriting. So you
    would use this see the pure HILTI AST resulting from the Spicy
    AST.

``codegen``
    Records activity during HILTI-to-C++ code generation.

``coercer``
    Records activity related to type and value coercion during AST
    resolving.

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
    Prints out details about the JIT process, which these days is
    primarily C++ compilation through, e.g.,  Clang or GCC.

``operator``
    Records activity related to operator resolution during AST
    resolving.

``optimizer``
    Records changes performed by the global optimizer.

``optimizer-collect``
    Records state collected from the AST by the global optimizer.

``parser``
    Prints out details about flex/bison processing.

``parser-builder``
    Records activity related to generating Spicy parsing code.

``resolver``
    Prints out a record of changes to the AST performed by the
    resolver pass.

``spicy-codegen``
    Records activity during lowering of Spicy code to HILTI code.

``type-unifier``
    Records activity related to type unification during AST resolving.
