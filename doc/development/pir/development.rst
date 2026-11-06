.. _pir_development:

===============
PIR Development
===============

PIR has a completely separate path from the standard Spicy/HILTI path in more ways than
one. First, PIR is in an entirely separate namespace and set of files, with only minimal
additions to Spicy's ``plugin.cc`` (among some other small additions). Second, PIR is
only executed with the ``--experimental-pir`` flag. Third, PIR will fall back to the
normal compilation path if it does not support the required constructs.

This will go over some important parts about how to work on PIR and what's left to do.

Working with PIR
================

The primary way to get PIR is using the flag with the ``spicy-pir`` debug stream:

.. code:: bash

	$ spicyc test.spicy -p --experimental-pir -D spicy-pir >/dev/null

This will also print  an unsupported debug message if PIR does not support that construct,
then proceed down the normal Spicy->Hilti lowerer:

.. code:: bash

	$ spicyc test.spicy -p --experimental-pir -D spicy-pir >/dev/null
    [debug/spicy-pir] found 1 root(s)
    [debug/spicy-pir] unsupported: parser unit 'Message' (only vectors of units are supported)
    [debug/spicy-pir] falling back to the standard code generator

Debugging
---------

Unfortunately, there isn't much to work with for debugging. The printer itself can be
accessed via a ``print`` function, like in LLDB::

	(lldb) expr -- spicy::detail::pir::ir::print(_package)
	(std::string) $0 = "type %0: void
	...

But, otherwise, there's not much to debug with. Here's a short wishlist for the future,
some of which have been inspired by the LLVM project:

#. Dump functions for the package, block, instructions, functions, etc. Preferably these
   are out-of-line and write to stderr, for the debugger, rather than returning a string.
#. Custom LLDB formatters
#. Per-instruction or per-block verification/optimization through a simple out-of-line
   function. This would be separate entry-points for the debugging functions.
#. Possible verification after each pass (opt-in, separate from verification at the end of
   optimization)
#. CFG viewer
#. Operand/use inspection
#. Print PIR only when changed after a given pass, and only the parts that changed

Current State
=============

PIR is currently in early stages, so coverage is narrow. Currently, PIR can represent
a subset of Spicy, only via HILTI as a backend. This subset includes some parsing
operations (a small number of integers, vectors, and subunits). It also includes basic
procedural code and control flow. PIR contains the building blocks to work with Zeek.

When new features are added, the list of capabilities outlined above should grow (at a
high-level). The list of features is deliberate and limited, based largely on what is
most important for benchmarks and real parsers.

PIR also has the building blocks for optimizations and thorough verification in place.
Once more language features are supported, optimizations can build alongside that work.

A reference interpreter is also on the table. This can live within Spicy and provide a
non-HILTI consumer for PIR, which would make it easier for backend writers to see how
to write their own. This reference interpreter could also provide useful evidence that
another path from C++ through HILTI would be worthwhile.
