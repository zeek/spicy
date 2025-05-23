This following summarizes the most important changes in recent Spicy releases.
For an exhaustive list of all changes, see the :repo:`CHANGES` file coming with
the distribution.

Version 1.14 (in progress)
==========================

.. rubric:: New Functionality

.. rubric:: Changed Functionality

.. rubric:: Bug fixes

.. rubric:: Documentation

Version 1.13
============

.. rubric:: New Functionality

- GH-1788: We now support decoding and encoding to UTF16, in particular the new
  ``UTF16LE`` and ``UTF16BE`` charsets for little and big endian encoding,
  respectively.

- GH-1961: We now support creating type values in Spicy code. The primary use
  case for this is to pass type information to host applications, and debugging.

  A type value is typically created from either ``typeinfo(TYPE)`` or
  ``typinfo(value)``, or coercion from an existing ID of a custom type like
  ``global T: type = MyStruct);``. The resulting value can be printed or stored
  in a variable of type ``type``, e.g., ``global bool_t: type = typeinfo(bool);``.

- GH-1971: Extend unit ``switch`` based on look-ahead to support blocks of items.

  In 1.12.0 we added support grouping related unit fields in blocks; there the
  primary use case were ``if`` blocks to group fields with identical
  dependencies. We now also support such blocks inside unit ``switch`` constructs
  with lookahead so one can write the following code:

  .. code-block:: spicy

    # Parses either `a` followed by another `a`, or `b`.
    type X = unit {
        switch {
            -> {
                : b"a";
                : b"a";
            }
            -> : b"b";
        };
    };

- GH-1538: Implement compound statements (``{...}``). This allows introducing
  local scopes, e.g., to group related code.

- GH-1946: ``string``'s ``encode`` method gained an optional ``errors`` argument to
  influence error handling. The parameter defaults to
  ``DecodeErrorStrategy::REPLACE`` reproducing the previous implicit behavior.

- GH-2010: ``bytes`` and ``string`` gained ``ends_with`` methods

- GH-1965: Add support for case-insensitive matching to regular expressions.

  By adding an ``i`` flag to a regular expression pattern, it will now be
  matched case-insensitively (e.g. ``/foobar/i``).

- GH-1962: Add ``spicy-dump`` option to enable profiling.

.. rubric:: Changed Functionality

- GH-1981, GH-1982, GH-1991: We now catch more user errors in defining function
  overloads. Previously these would likely (hopefully) have failed in C++ compilation
  down the line, but are now cleanly rejected.

- GH-1977: We now reject function overloads which only differ in their return type.

- GH-1991: We now reject function prototypes without ``&cxxname``.

  Since in Spicy global declarations can be in any order there is no need to
  introduce a function with a prototype if it is declared later. The only valid
  use case for function prototypes was if the function was implemented in C++
  and bound to the Spicy name with ``&cxxname``.

- We have cleaned up our implementation for runtime type information, primarily
  intended for custom host applications.

  - ``type_info::Value`` instances obtained through runtime type introspection
    can now be rendered to a user-facing representation with a new ``to_string``
    method.

  - The runtime representation was changed to correctly encode that tuple
    elements can remain unset. A Spicy-side tuple ``tuple<T1, T2, T3>`` now gets
    turned into ``std::tuple<std::optional<T1>, std::optional<T2>, std::optional<T3>>``
    which captures the full semantics.

  - We added type information for types previously not exposed, namely ``Null``,
    ``Nothing`` and ``List``. We also fixed the exposed type information for
    ``result<void>``.

- GH-2011: We have optimized allocations for unit fields extracting vectors
  which should speed up extracting especially small and medium-size vectors.
- GH-2035: We have dropped support for Ubuntu 20.04 (Focal Fossa) since it has
  reached end of standard support upstream.
- GH-2026: Speed up matching of character classes in regexps

.. rubric:: Bug fixes

- GH-1580: Catch when functions aren't called.
- GH-1961: Fix generated C++ prototype header.
- GH-1966: Reject anonymous units in variables and fields.
- GH-1967: Fix inactive stack size check during module initialization.
- GH-1968: Fix coercion of function call arguments.
- GH-1976: Fix unit ``&max-size`` not returning to proper loc.
- GH-2007: Fix using ``&try`` with ``&max-size``, and potentially other cases.
- GH-2016: Fix ``&size`` expressions evaluating multiple times.
- GH-2038: Prevent escape of non-HILTI exception in lower-level driver functions.
- GH-2047: Make sure ``bytes::to[U]Int`` returns runtime integers.
- GH-2049: Add ``#include <cstdint>`` for fixed-width integers

.. rubric:: Documentation

- GH-1155: Document iteration over maps/set/vectors.
- GH-1963: Document ``assert-exception``.
- GH-1964: Document use of ``$$`` inside ``&{while,until,until-including}``.
- GH-1973: Remove documentation of unsupported ``&nosub``.
- GH-1974: Add documentation on how to interpret stack traces involving fibers.
- GH-1975: Fix possibly-incorrect custom host compile command
- GH-2039: Touchup docs style section.
- GH-1970, GH-2003: Fix minor typos in documentation.

Version 1.12
============

.. rubric:: New Functionality

- We now support ``if`` around a block of unit items:

  .. code-block:: spicy

        type X = unit {
             x: uint8;

             if ( self.x == 1 ) {
                 a1: bytes &size=2;
                 a2: bytes &size=2;
             };
        };

  One can also add an ``else``-block:

  .. code-block:: spicy

        type X = unit {
             x: uint8;

             if ( self.x == 1 ) {
                 a1: bytes &size=2;
                 a2: bytes &size=2;
             }
             else {
                 b1: bytes &size=2;
                 b2: bytes &size=2;
             };
        };

- We now support attaching an ``%error`` handler to an individual
  field:

  .. code-block:: spicy

       type Test = unit {
           a: b"A";
           b: b"B" %error { print "field B %error", self; }
           c: b"C";
       };

  With input ``AxC``, that handler will trigger, whereas with ``ABx``
  it won't. If the unit had a unit-wide ``%error`` handler as well,
  that one would trigger in both cases (i.e., for ``b``, in addition
  to its field local handler).

  The handler can also be provided separately from the field:

  .. code-block:: spicy

       on b %error { ... }

  In that separate version, one can receive the error message as well by
  declaring a corresponding string parameter:

  .. code-block:: spicy

       on b(msg: string) %error { ... }

  This works externally, from outside the unit, as well:

  .. code-block:: spicy

       on Test::b(msg: string) %error { ... }

- GH-1856: We added support for specifying a dedicated error message for ``requires`` failures.

  This now allows creating custom error messages when a ``&require``
  condition fails. Example:

  .. code-block:: spicy

      type Foo = unit {
          x: uint8 &requires=($$ == 1 : error"Deep trouble!'");

          # or, shorter:
          y: uint8 &requires=($$ == 1 : "Deep trouble!'");
      };

  This is powered by a new condition test expression ``COND : ERROR``.

- We reworked C++ code generation so now many parsers should compile faster.
  This is accomplished by both improved dependency tracking when emitting C++
  code for a module as well as by a couple of new peephole optimization passes
  which additionally reduced the emitted code.

.. rubric:: Changed Functionality

- Add ``CMAKE_CXX_FLAGS`` to ``HILTI_CONFIG_RUNTIME_LD_FLAGS``.
- Speed up compilation of many parsers by streamlining generated C++ code.
- Add ``starts_with``, ``split``, ``split1``, ``lower`` and ``upper`` methods to ``string``.
- GH-1874: Add new library function ``spicy::bytes_to_mac``.
- Optimize ``spicy::bytes_to_hexstring`` and ``spicy::bytes_to_mac``.
- Improve validation of attributes so incompatible or invalid attributes should be rejected more reliably.
- Optimize parsing for ``bytes`` of fixed size as well as literals.
- Add a couple of peephole optimizations to reduce emitted C++ code.
- GH-1790: Provide proper error message when trying access an unknown unit field.
- GH-1792: Prioritize error message reporting unknown field.
- GH-1803: Fix namespacing of ``hilti`` IDs in Spicy-side diagnostic output.
- GH-1895: Do no longer escape backslashes when printing strings or bytes.
- GH-1857: Support ``&requires`` for individual vector items.
- GH-1859: Improve error message when a unit parameter is used as a field.
- GH-1898: Disallow attributes on "type aliases".
- GH-1938: Deprecate ``&count`` attribute.
- GH-1928: Deprecate ``&anchor`` with regular expression constructors.
- GH-1935: Allow defining parser alias names when running spicy-driver.

.. rubric:: Bug fixes

- GH-1815: Disallow expanding limited ``View``'s again with ``limit``.
- Fix ``to_uint(ByteOrder)`` for empty byte ranges.
- Fix undefined shifts of 32bit integer in ``toInt()``.
- GH-1817: Prevent null ptr dereference when looking on nodes without ``Scope``.
- Fix use of move'd from variable.
- GH-1823: Don't qualify magic linker symbols with C++ namespace.
- Fix diagnostics seen when compiling with GCC.
- GH-1852: Fix ``skip`` with units.
- GH-1832: Fail for vectors with bytes but no stop.
- GH-1860: Fix parsing for vectors of literals.
- GH-1847: Fix resynchronization issue with trimmed input.
- GH-1844: Fix nested look-ahead parsing.
- GH-1842: Fix when input redirection becomes visible.
- GH-1846: Fix bug with captures groups.
- GH-1875: Fix potential nullptr dereference when comparing streams.
- GH-1867: Fix infinite loops with recursive types.
- GH-1868: Associate source code locations with current fiber instead of current thread.
- GH-1871: Fix ``&max-size`` on unit containing a ``switch``.
- GH-1791: Fix usage of ``&convert`` with unit's requiring parameters.
- GH-1858: Fix the literals parsers not following coercions.
- GH-1893: Encompass child node's location in parent.
- GH-1919: Validate that sets are sortable.
- GH-1918: Fix potential segfault with stream iterators.
- GH-1856: Disallow dereferencing a ``result<void>`` value.
- Fix issue with type inference for ``result`` constructor.
- GH-1933: Fix ``HILTI_CXX_FLAGS`` for when multiple flags are passed.
- GH-1829: Catch integer shifts exceeding the width of the operand.

.. rubric:: Documentation

- Redo error handling docs
- Document ``continue`` statements.
- GH-1063: Document arguments to ``new`` operator.
- Updates ``<bytes>.to_int()``/``<bytes>.to_uint()`` documentation.
- GH-1914: Make ``$$`` documentation more precise.
- Fix doc code snippet that won't compile.

Version 1.11
============

.. rubric:: New Functionality

- GH-3779: Add ``%sync_advance`` hook.

  This adds support for a new unit hook:

  .. code-block:: spicy

      on %sync_advance(offset: uint64) {
          ...
      }

  This hook is called regularly during error recovery when synchronization
  skips over data or gaps while searching for a valid synchronization point. It
  can be used to check in on the synchronization to, e.g., abort further
  processing if it just keeps failing. ``offset`` is the current position
  inside the input stream that synchronization just skipped to.

  By default, "called regularly" means that it's called every 4KB of
  input skipped over while searching for a synchronization point. That
  value can be changed by setting a unit property
  ``%sync-advance-block-size = <number of bytes>``.

  As an additional minor tweak, this also changes the name of what used
  to be the ``__gap__`` profiler to now be called ``__sync_advance`` because
  it's profiling the time spent in skipping data, not just gaps.

- Add unit method ``stream()`` to access current input stream, and stream method
  ``statistics()`` to retrieve input statistics.

  This returns a struct of the following type, reflecting the input
  seen so far:

  .. code-block:: spicy

      type StreamStatistics = struct {
          num_data_bytes: uint64;     ## number of data bytes processed
          num_data_chunks: uint64;    ## number of data chunks processed, excluding empty chunks
          num_gap_bytes: uint64;      ## number of gap bytes processed
          num_gap_chunks: uint64;     ## number of gap chunks processed, excluding empty chunks
      };

- GH-1750: Add ``to_real`` method to ``bytes``.

  This interprets the data as representing an ASCII-encoded floating
  point number and converts that into a ``real``. The data can be in
  either decimal or hexadecimal format. If it cannot be parsed as
  either, throws an ``InvalidValue`` exception.

- GH-1608: Add ``get_optional`` method to maps.

  This returns an ``optional`` value either containing the map's element for the
  given key if that entry exists, or an unset ``optional`` if it does not.

- GH-90/GH-1733: Add ``result`` and ``spicy::Error`` types to Spicy to
  facilitate error handling.

.. rubric:: Changed Functionality

- The Spicy compiler has become a bit more strict and is now rejecting
  some ill-defined code constructs that previous versions ended up
  letting through. Specifically, the following cases will need
  updating in existing code:

    - Identifiers from the (internal) ``hilti::`` namespace are no
      longer accessible. Usually you can just scope them with
      ``spicy::`` instead.

    - Previous versions did not always enforce constness as it should
      have. In particular, function parameters could end up being
      mutable even when they weren't declared as ``inout``. Now ``inout``
      is required for supporting any mutable operations on a
      parameter, so make sure to add it where needed.

    - When using unit parameters, the type of any ``inout`` parameters
      now must be unit itself. To pass other types into a unit so that
      they can be modified by the unit, use reference instead of
      ``inout``. For example, use ``type Foo = unit(s: sink&)`` instead of
      ``type Foo = unit(inout: sink)``. See
      https://docs.zeek.org/projects/spicy/en/latest/programming/parsing.html#unit-parameters
      for more.

- The Spicy compiler new uses a more streamlined storage and access scheme to
  represent source code. This speeds up work up util C++ source translation
  (e.g., faster time to first error message during development).

- ``spicyc`` options ``-c`` and ``-l`` no longer support compiling
  multiple Spicy source files to C++ code individually to then build
  them all together. This was a rarely used feature and actually already
  broken in some situations. Instead, use ``spicyc -x`` to produce the
  C++ code for all needed Spicy source files at once. ``-c`` and
  ``-l`` remain available for debugging purposes.

- The ``spicyc`` option ``-P`` now requires a prefix argument that
  sets the C++ namespace, just like ``-x <prefix>`` does. This is so
  that the prototypes match the actual code generated by ``-x``. To
  get the same identifiers as before, use an empty prefix (``-P ""``).

- GH-1763: Restrict initialization of ``const`` values to literals. This means
  that e.g., ``const`` values cannot be initialized from other ``const`` values or
  function calls anymore.
- ``result`` and ``network`` are now keywords and cannot be used anymore as
  user-specified indentifiers.
- GH-1661: Deprecate usage of ``&convert`` with ``&chunked``.
- GH-1657: Reduce data copying when passing data to the driver.
- GH-1501: Improve some error messages for runtime parse errors.
- GH-1655: Reject joint usage of filters and look-ahead.
- GH-1675: Extend runtime profiling to measure parser input volume.
- GH-1624: Enable optimizations when running ``spicy-build``.

.. rubric:: Bug fixes

- GH-1759: Fix ``if``-condition with ``switch`` parsing.
- Fix Spicy's support for ``network`` type.
- GH-1598: Enforce that the argument ``new`` is either a type or a
  ctor.
- GH-1742, GH-1760: Unroll constructors of big containers in generated code. We previously would
  generate code which would be expensive to compiler for some compilers. We now
  generate more friendly code.
- GH-1745: Fix C++ initialization of global constants through global functions.
- GH-1743: Use a checked cast for ``map``'s ``in`` operator.
- GH-1664: Fix ``&convert`` typing issue with bit ranges.
- GH-1724: Fix skipping in size-constrained units. We previously could skip too
  much data if ``skip`` was used in a unit with a global ``&size``.
- Fix incremental skipping. We previously would incorrectly compute the amount
  of data to skip which could have potentially lead to the parser consuming
  more data than available.
- GH-1586: Make skip productions behave like the production they are wrapping.
- GH-1711: Fix forwarding of a reference unit parameter to a non-reference parameter.
- GH-1599: Fix integer increment/decrement operators require mutable arguments.
- GH-1493: Support/fix public type aliases to units.

.. rubric:: Documentation

- Add new section with guidelines and best practices. This focuses on
  performance for now, but may be extended with other areas alter. Much of the
  content was contributed by Corelight Labs.
- Fix documented type mapping for integers.
- Document generic operators.

Version 1.10
============

.. rubric:: New Functionality

.. rubric:: Changed Functionality

- Numerous improvements to improve throughput of generated parsers.

  For this release we have revisited the code typically generated for parsers
  and the runtime libraries they use with the goal of improving throughput of
  parsers at runtime. Coarsely summarized this work was centered around

  - reduction of allocations during parsing
  - reduction of data copies during parsing
  - use of dedicated, hand-check implementations for automatically generated
    code to avoid overhead from safety checks in the runtime libraries

  With these changes we see throughput improvements of some parsers in the
  range of 20-30%. This work consisted of numerous incremental changes, see
  ``CHANGES`` for the full list of changes.

- GH-1667: Always advance input before attempting resynchronization.

  When we enter resynchronization after hitting a parse error we
  previously would have left the input alone, even though we know it fails
  to parse. We then relied fully on resynchronization to advance the
  input.

  With this patch we always forcibly advance the input to the next non-gap
  position. This has no effect for synchronization on literals, but allows
  it to happen earlier for regular expressions.

- GH-1659: Lift requirement that ``bytes`` forwarded from filter be mutable.

- GH-1489: Deprecate &bit-order on bit ranges.

  This had no effect and allowing it may be confusing to users. Deprecate it
  with the idea of eventual removal.

- Extend location printing to include single-line ranges.

  For a location of, e.g., "line 1, column 5 to 10", we now print
  ``1:5-1:10``, whereas we used to print it as only ``1:5``, hence dropping
  information.

- GH-1500: Add ``+=`` operator for ``string``.

  This allows appending to a ``string`` without having to allocate a new
  string. This might perform better most of the time.

- GH-1640: Implement skipping for any field with known size.

  This patch adds ``skip`` support for fields with ``&size`` attribute or of
  builtin type with known size. If a unit has a known size and it is
  specified in a ``&size`` attribute this also allows to skip over unit
  fields.

.. rubric:: Bug fixes

- GH-1605: Allow for unresolved types for set ``in`` operator.

- GH-1617: Fix handling of ``%synchronize-*`` attributes for units in lists.

  We previously would not detect ``%synchronize-at`` or ``%synchronize-from``
  attributes if the unit was not directly in a field, i.e., we mishandled
  the common case of synchronizing on a unit in a list.

  We now handle these attributes, regardless of how the unit appears.

- GH-1585: Put closing of unit sinks behind feature guard.

  This code gets emitted, regardless of whether a sink was actually
  connected or not. Put it behind a feature guard so it does not enable
  the feature on its own.

- GH-1652: Fix filters consuming too much data.

  We would previously assume that a filter would consume all available
  data. This only holds if the filter is attached to a top-level unit, but
  in general not if some sub-unit uses a filter. With this patch we
  explicitly compute how much data is consumed.

- GH-1668: Fix incorrect data consumption for ``&max-size``.

  We would previously handle ``&size`` and ``&max-size`` almost identical
  with the only difference that ``&max-size`` sets up a slightly larger view
  to accommodate a sentinel. In particular, we also used identical code to
  set up the position where parsing should resume after such a field.

  This was incorrect as it is in general impossible to tell where parsing
  continues after a field with ``&max-size`` since it does not signify a fixed
  view like ``&size``. We now compute the next position for a ``&max-size``
  field by inspecting the limited view to detect how much data was extracted.

- GH-1522: Drop overzealous validator.

  A validator was intended to reject a pattern of incorrect parsing of vectors,
  but instead ending up rejecting all vector parsing if the vector elements
  itself produced vectors. We dropped this validation.

- GH-1632: Fix regex processing using ``{n,m}`` repeat syntax being off by one

- GH-1648: Provide meaningful unit ``__begin`` value when parsing starts.

  We previously would not provide ``__begin`` when starting the initial
  parse. This meant that e.g., ``offset()`` was not usable if nothing ever
  got parsed.

  We now provide a meaningful value.

- Fix skipping of literal fields with condition.

- GH-1645: Fix ``&size`` check.

  The current parsing offset could legitimately end up just beyond the
  ``&size`` amount.

- GH-1634: Fix infinite loop in regular expression parsing.

.. rubric:: Documentation

- Update documentation of ``offset()``.

- Fix docs namespace for symbols from ``filter`` module.

  We previously would document these symbols to be in ``spicy`` even though
  they are in ``filter``.

- Add bitfield examples.

Version 1.9
===========

.. rubric:: New Functionality

- GH-1468: Allow to directly access members of anonymous bitfields.

  We now automatically map fields of anonymous bitfields into their containing unit.

  .. code-block:: spicy

    type Foo = unit {
        : bitfield(8) {
            x: 0..3;
            y: 4..7;
        };

        on %done {
            print self.x, self.y;
        }
    };

- GH-1467: Support bitfield constants in Spicy for parsing.

  One can now define bitfield "constants" for parsing by providing
  integer expressions with fields:

  .. code-block:: spicy

      type Foo = unit {
        x: bitfield(8) {
          a: 0..3 = 2;
          b: 4..7;
          c: 7 = 1;
        };

  This will first parse the bitfield as usual and then enforce that the
  two bit ranges that are coming with expressions (i.e., ``a`` and ``c``)
  indeed containing the expected values. If they don't, that's a parse
  error.

  We also support using such bitfield constants for look-ahead parsing:

  .. code-block:: spicy

      type Foo = unit {
        x: uint8[];
        y: bitfield(8) {
          a: 0..3 = 4;
          b: 4..7;
        };
      };

  This will parse uint8s until a value is discovered that has its bits
  set as defined by the bitfield constant.

  (We use the term "constant" loosely here: only the bits with values
  are actually enforced to be constant, all others are parsed as usual.)

- GH-1089, GH-1421: Make ``offset()`` independent of random access functionality.

  We now store the value returned by ``offset()`` directly in the
  unit instead of computing it on the fly when requested from ``cur - begin``.
  With that ``offset()`` can be used without enabling random access
  functionality on the unit.

- Add support for passing arbitrary C++ compiler flags.

  This adds a magic environment variable ``HILTI_CXX_FLAGS`` which if set
  specifies compiler flags which should be passed during C++ compilation
  after implicit flags. This could be used to e.g., set defines, or set
  low-level compiler flags.

  Even with this flag, for passing include directories one should still
  use ``HILTI_CXX_INCLUDE_DIRS`` since they are searched before any
  implicitly added paths.

- GH-1435: Add bitwise operators ``&``, ``|``, and ``^`` for booleans.

- GH-1465: Support skipping explicit ``%done`` in external hooks.

  Assuming ``Foo::X`` is a unit type, these two are now equivalent:

  .. code-block:: spicy

      on Foo::X::%done   { }
      on Foo::X          { }

.. rubric:: Changed Functionality

- GH-1567: Speed up runtime calls to start profilers.

- GH-1565: Disable capturing backtraces with HILTI exceptions in non-debug builds.

- GH-1343: Include condition in ``&requires`` failure message.

- GH-1466: Reject uses of ``self`` in unit ``&size`` and ``&max-size`` attribute.

  Values in ``self`` are only available after parsing has started while
  ``&size`` and ``&max-size`` are consumed before that. This means that any
  use of ``self`` and its members in these contexts would only ever see
  unset members, so it should not be the intended use.

- GH-1485: Add validator rejecting unsupported multiple uses of attributes.

- GH-1465: Produce better error message when hooks are used on a unit field.

- GH-1503: Handle anonymous bitfields inside ``switch`` statements.

  We now map items of anonymous bitfields inside a ``switch`` cases into
  the unit namespace, just like we already do for top-level fields. We
  also catch if two anonymous bitfields inside those cases carry the
  same name, which would make accesses ambiguous.

  So the following works now:

  .. code-block:: spicy

      switch (self.n) {
          0 -> : bitfield(8) {
              A: 0..7;
          };
          * -> : bitfield(8) {
              B: 0..7;
          };
      };

  Whereas this does not work:

  .. code-block:: spicy

      switch (self.n) {
          0 -> : bitfield(8) {
              A: 0..7;
          };
          * -> : bitfield(8) {
              A: 0..7;
          };
      };

- GH-1571: Remove trimming inside individual chunks.

  Trimming a ``Chunk`` (always from the left) causes a lot of internal work
  with only limited benefit since we manage visibility with a ``stream::View``
  on top of a ``Chunk`` anyway.

  We now trimming only removes a ``Chunk`` from a ``Chain``, but does not
  internally change individual the ``Chunk`` anymore. This should benefit
  performance but might lead to slightly increased memory use, but callers
  usually have that data in memory anyway.

- Use ``find_package(Python)`` with version.

  Zeek's configure sets ``Python_EXECUTABLE`` has hint, but Spicy is using
  ``find_package(Python3)`` and would only use ``Python3_EXECUTABLE`` as hint.
  This results in Spicy finding a different (the default) Python executable
  when configuring Zeek with ``--with-python=/opt/custom/bin/python3``.

  Switch Spicy over to use ``find_package(Python)`` and add the minimum
  version so it knows to look for ``Python3``.

.. rubric:: Bug fixes

- GH-1520: Fix handling of ``spicy-dump --enable-print``.

- Fix spicy-build to correctly infer library directory.

- GH-1446: Initialize generated struct members in constructor body.

- GH-1464: Add special handling for potential ``advance`` failure in trial mode.

- GH-1275: Add missing lowering of Spicy unit ctor to HILTI struct ctor.

- Fix rendering in validation of ``%byte-order`` attribute.

- GH-1384: Fix stringification of ``DecodeErrorStrategy``.

- Fix handling of ``--show-backtraces`` flag.

- GH-1032: Allow using using bitfields with type declarations.

- GH-1484: Fix using of ``&convert`` on bitfields.

- GH-1508: Fix returned value for ``<unit>.position()``.

- GH-1504: Use user-inaccessible chars for encoding ``::`` in feature variables.

- GH-1550: Replace recursive deletion with explicit loop to avoid stack overflow.

- GH-1549: Add feature guards to accesses of a unit's ``__position``.

.. rubric:: Documentation

- Move Zeek-specific documentation into Zeek documentation.

- Clarify error handling docs.

- Mention unit switch statements in conditional parsing docs.

Version 1.8
===========

.. rubric:: New Functionality

- Add new ``skip`` keyword to let unit items efficiently skip over uninteresting data.

  For cases where your parser just needs to skip over some data, without
  needing access to its content, Spicy provides a ``skip`` keyword to
  prefix corresponding fields with:

  .. spicy-code:: skip.spicy

      module Test;

      public type Foo = unit {
          x: int8;
           : skip bytes &size=5;
          y: int8;
          on %done { print self; }
      };

  ``skip`` works for all kinds of fields but is particularly efficient
  with ``bytes`` fields, for which it will generate optimized code
  avoiding the overhead of storing any data.

  ``skip`` fields may have conditions and hooks attached, like
  any other fields. However, they do not support ``$$`` in
  expressions and hooks.

  For readability, a ``skip`` field may be named (e.g., ``padding: skip
  bytes &size=3;``), but even with a name, its value cannot be accessed.

  ``skip`` fields extend support for ``void`` with attributes fields which are now deprecated.

- Add runtime profiling infrastructure.

  This add an option ``--enable-profiling`` to the HILTI and Spicy compilers. Use
  of the option does two things: (1) it sets a flag enabling inserting
  additional profiling instrumentation into generated C++ code, and (2) it
  enables using instrumentation for recording profiling information during
  execution of the compiled code, including dumping out a profiling report at
  the end. The profiling information collected includes time spent in HILTI
  functions as well as for parsing Spicy units and unit fields.

.. rubric:: Changed Functionality

- Optimizations for improved runtime performance.

  This release contains a number of changes to improve the runtime performance
  of generated parsers. This includes tweaks for generating more performant
  code for parsers, low-level optimizations of types in to runtime support
  library as well as fine-tuning of parser execution at runtime.

- Do not force locale on users of libhilti.
- Avoid expensive checked iterator for internal ``Bytes`` iteration.
- GH-1089: Allow to use ``offset()`` without enabling full random-access support.
- GH-1394: Fix C++ normalization of generated enum values.
- Disallow using ``$$`` with anonymous containers.

.. rubric:: Bug fixes

- GH-1386: Prevent internal error when passed invalid context.
- Fix potential use-after-move bug.
- GH-1390: Initialize ``Bytes`` internal control block for all constructors.
- GH-1396: Fix regex performance regression introduced by constant folding.
- GH-1399: Guard access to unit ``_filters`` member with feature flag.
- GH-1421: Store numerical offset in units instead of iterator for position.
- GH-1436: Make sure ``Bytes::sub`` only throws HILTI exceptions.
- GH-1447: Do not forcibly make ``strong_ref`` ``in`` function parameters immutable.
- GH-1452: Allow resolving of unit parameters before ``self`` is fully resolved.
- Make sure Spicy runtime config is initialized after ``spicy::rt::init``.
- Adjustments for building with GCC-13.

.. rubric:: Documentation

- Document how to check whether an ``optional`` value is set.
- Preserve indention when extracting comments in doc generation.
- Fix docs for long-form of ``-x`` flag to spicyc.

Version 1.7
===========

.. rubric:: New Functionality

- Support Zeek-style documentation strings in Spicy source code.

- Provide ability for host applications to initiate runtime's module-pre-init phase manually.

- Add DPD-style ``spicy::accept_input()`` and ``spicy::decline_input()``.

- Add driver option to output full set of generated C++ files.

- GH-1123: Support arbitrary expression as argument to type constructors, such as ``interval(...)``.

.. rubric:: Changed Functionality

- Search ``HILTI_CXX_INCLUDE_DIRS`` paths before default include paths.

- Search user module paths before system paths.

- Streamline runtime exception hierarchy.

- Fix bug in cast from ``real`` to ``interval``.

- GH-1326: Generate proper runtime types for enums.

- GH-1330: Reject uses of imported module IDs as expression.

.. rubric:: Bug fixes

- GH-1310: Fix ASAN false positive with GCC.

- GH-1345: Improve runtime performance of stream iteration.

- GH-1367: Use unique filename for all object files generated during JIT.

- Remove potential race during JIT when using ``HILTI_CXX_COMPILER_LAUNCHER``.

- GH-1349: Fix incremental regexp matching for potentially empty results.

.. rubric:: Documentation

Version 1.6
===========

.. rubric:: New Functionality

- GH-1249: Allow combining ``&eod`` with ``&until`` or ``&until-including``.

- GH-1251: When decoding bytes into a string using a given character
  set, allow caller to control error handling.

  All methods taking a charset parameters now take an additional
  enum selecting 1 of 3 possible error handling strategies in case a
  character can't be decoded/represented: ``STRICT`` throws an error,
  ``IGNORE`` skips the problematic character and proceeds with the
  next, and ``REPLACE`` replaces the problematic character with a safe
  substitute. ``REPLACE`` is the default everywhere now, so that by
  default no errors are triggered.

  This comes with an additional functional change for the ASCII
  encoding: we now consistently sanitize characters that ASCII can't
  represent when in ``REPLACE``/``IGNORE`` modes (and, hence, by
  default), and trigger errors in ``STRICT`` mode. Previously, we'd
  sometimes let them through, and never triggered any errors. This
  also fixes a bug with the ASCII encoding sometimes turning a
  non-printable character into multiple repeated substitutes.

- GH-1294: Add library function to parse an address from string or bytes.

- HLTO files now perform a version check when loaded.

  We previously would potentially allow building a HLTO file against one
  version of the Spicy runtime, and then load it with a different version. If
  exposed symbols matched loading might have succeeded, but could still have lead
  to sublte bugs at runtime.

  We now embed a runtime version string in HLTO files and reject loading HLTO
  files into a different runtime version. We require an exact version match.

- New ``pack`` and ``unpack`` operators.

  These provide
  low-level primitives for transforming a value into, or out of, a
  binary representations, see :ref:`the docs <packing>` for details.

.. rubric:: Changed Functionality

- GH-1236: Add support for adding link dependencies via ``--cxx-link``.

- GH-1285: C++ identifiers referenced in ``&cxxname`` are now automatically
  interpreted to be in the global namespace.

- Synchronization-related debug messages are now logged to the
  ``spicy-verbose`` stream. We added logging of successful synchronization.

- Downgrade required Flex version.
  We previously required at least flex-2.6.0; we can now build against flex-2.5.37.

- Improve C++ caching during JIT.

  We improved caching behavior via ``HILTI_CXX_COMPILER_LAUNCHER`` if the
  configuration of ``spicyc`` was changed without changing the C++ file
  produced during JIT.

- ``hilti::rt::isDebugVersion`` has been removed.

- The ``-O | --optimize`` flag has been removed from command line tools.

  This was already a no-op without observable side-effects.

- GH-1311: Reject use of ``context()`` unit method if unit does not declare a
  context with ``%context``.

- GH-1319: Unsupported unit variable attributes are now rejected.

- GH-1299: Add validator for bitfield field ranges.

- We now reject uses of ``self`` as an ID.

- GH-1233: Reject key types for maps that can't be sorted.

- Fix validator for field ``&default`` expression types for constness.

  When checking types of field ``&default`` expressions we previously would
  also consider their constness. This breaks e.g., cases where the used
  expression is not a LHS like the field the ``&default`` is defined for,

  .. code-block:: spicy

     type X = unit {
         var x: bytes = b"" + a;
     };

  We now do not consider constness in the type check anymore. Since fields are
  never const this allows us to set a ``&default`` with constant expressions as
  well.

.. rubric:: Bug fixes

- GH-1231: Add special handling for potential ``advance`` failure in trial mode.

- GH-1115, GH-1196: Explicitly type temporary value used by ``&max_size``
  logic.

- GH-1143, GH-1220: Add coercion on assignment for optionals that
  only differ in constness of their inner types.

- GH-1230: Add coercion to default argument of ``map::get``.

- GH-1234, GH-1238: Fix assertions with anonymous struct constructor.

- GH-1248: Fix ``stop`` for unbounded loop.

- GH-1250: Fix internal errors when seeing unsupported character
  classes in regular expression.

- GH-1170: Fix contexts not allowing being passed ``inout``.

- GH-1266: Fix wrong type for Spicy-side ``self`` expression.

- GH-1261: Fix inability to access unit fields through ``self`` in
  ``&convert`` expressions.

- GH-1267: Install only needed headers from bundled SafeInt library.

- GH-1227: Fix code generation when a module's file could be imported through different means.

- GH-1273: Remove bundled code licensed under `CPOL license <https://www.codeproject.com/info/cpol10.aspx>`_.

- GH-1303: Fix potentially late synchronization when jumping over gaps during synchronization.

- Do not force gold linker with user-provided linker flags or when built as a CMake subproject.

- Improve efficiency of ``startsWith`` for long inputs.

.. rubric:: Documentation

- The documentation now reflects Zeek package manager Spicy feature templates.

- The documentation for bitfields was clarified.

- Documentation for casts from integers to boolean was added.

- We added documentation for how to expose custom C++ code in Spicy.

- Update doc link to commits mailing list.

- Clarify that ``%context`` can only be used in top-level units.

- Clarify that ``&until`` consumes the delimiter.

- GH-1240: Clarify docs on ``SPICY_VERSION``.

- Add FAQ item on source locations.

- Add example for use of ``?.``.

Version 1.5
===========

.. rubric:: New Functionality

- GH-1179: Cap parallelism use for JIT background jobs.

  During JIT, we would previously launch all compilation jobs in parallel. For
  projects using many modules this could have lead to resource contention which
  often forced users to use sequential compilation with
  ``HILTI_JIT_SEQUENTIAL``. We now by default cap the number of parallel
  background jobs at the number of logical cores. This can be parameterized
  with the environment variable ``HILTI_JIT_PARALLELISM`` which for
  ``HILTI_JIT_PARALLELISM=1`` reproduces ``HILTI_JIT_SEQUENTIAL``.

- GH-1134: Add support for ``synchronize-at`` and ``synchronize-after`` properties.

  These unit properties allow specifying a literal which should be searched for
  during error recovery. If the respective unit is used as a synchronize point
  during error recovery, i.e., it is used as a field which is marked
  ``&synchronize``, input resynchronization during error recovery will seek to
  the next position of this pattern in the input stream.

- GH-1209: Provide error message to ``%error`` handler.

    We now allow to optionally provide a string parameter with
    ``%error`` that will receive the associated error message:

  .. code-block:: spicy

    on %error(msg: string) { print msg; }

.. rubric:: Changed Functionality

- GH-1184: Allow more cache hits if only a few modules are changed in multi-module compilation.

- GH-1208: Incremental performance tweaks for JIT.

- GH-1197: Make handling of sanitizer workarounds more granular.

.. rubric:: Bug fixes

- GH-1150: Preserve additional permissions from umask when generating HLTO files.

- GH-1154: Add stringificaton of ``Map::value_type``.

- GH-1080: Reject constant declarations at non-global scope.

- GH-1164: Make compiler plugin initialization explicit.

- GH-1050: Update location when entering most parser methods.

- GH-1187: Fix support for having multiple source modules of the same name.

- GH-1197: Prevent too early integer overflow in pow.

- GH-1201: Adjust removal of symlinks on install for ``DESTDIR``.

- GH-1203: Allow changing ``DESTDIR`` between configure and install time.

- GH-1204: Remove potential use-after-move.

- GH-1210: Prevent unnecessarily executable stack with GNU toolchain.

- GH-1206: Fix detection of recursive dependencies.

- GH-1217: Produce ``hilti::rt::Bool`` when casting to boolean.

- GH-1224: Fix import segfault.

.. rubric:: Documentation

- GH-44: Update docs for spicy-plugin rename ``_Zeek::Spicy`` -> ``Zeek::Spicy``.

- GH-1183: Update docs for Discourse migration.

- GH-1205: Update Spicy docs for now being built into Zeek.

Version 1.4
===========

.. rubric:: New Functionality

- Add support for recovery from parse errors or incomplete input

  This release adds support for recovering from parse errors or incomplete
  input (e.g., gaps or partial connections). Grammars can denote unit
  synchronization points with a ``&synchronize`` attribute. If an error is
  encountered while extracting a previous fields, parsing will attempt to
  resynchronize the input at that point. The synchronization result needs to be
  checked and confirmed or rejected explicitly; a number of hooks are provided
  for that. See :ref:`the docs <error_recovery>` for details.

- Remove restriction that units used as sinks need to be ``public``

-  Uses ``ccache`` for C++ compilation during JIT if Spicy itself was configured to use ``ccache``

  Spicy spends a considerable amount of JIT time compiling generated C++ code.
  This work can be cached if neither inputs nor any of the used flags have
  changed so that subsequent JIT runs can complete much faster.

  We now automatically cache many C++ compilation artifacts with ``ccache`` if
  Spicy itself was configured with e.g.,
  ``--with-hilti-compiler-launcher=ccache``. This behavior can be controlled or
  disabled via the ``HILTI_CXX_COMPILER_LAUNCHER`` environment variable.

- GH-842: Add Spicy support for struct initialization.

- GH-1036: Support unit initialization through a struct constructor expression.

.. rubric:: Changed Functionality

- GH-1074: ``%random-access`` is now derived automatically from uses and
  declaring it explicitly has been deprecated.

- GH-1072: Disallow enum declarations with non-unique values.

  It is unclear what code should be generated when requested to convert an
  integer value to the following enum:

  .. code-block:: spicy

      type E = enum {
          A = 1,
          B = 2,
          C = 1,
      };

  For ``1`` we could produce either ``E::A`` or ``E::C`` here.

  Instead of allowing this ambiguity we now disallow enums with non-unique values.

.. rubric:: Bug fixes

- Prevent exception if cache directory is not readable.

- Propagate failure from ``cmake`` up to ``./configure``.

- GH-1030: Make sure types required for globals are declared before being used.

- Fix potentially use-after-free in stringification of ``stream::View``.

- GH-1087: Make ``offset`` return correct value even before parsing of field.

.. rubric:: Documentation

Version 1.3
===========

.. rubric:: New Functionality

- Add optimizer removing unused ``%random-access`` or ``%filter`` functionality

  If a unit has e.g., a ``%random-access`` attribute Spicy emits additional
  code to track and update offsets. If the ``%random-access`` functionality is
  not used this leads to unneeded code being emitted which causes unneeded
  overhead, both during JIT and during execution.

  We now emit such feature-dependent code under a feature flag (effectively a
  global boolean constant) which is by default *on*. Additionally, we added an
  optimizer pass which detects whether a feature is used and can disable unused
  feature functionality (switching the feature flag to *off*), and can then
  remove unreachable code behind such disabled feature flags by performing
  basic constant folding.

- Add optimizer pass removing unused sink functionality

  By default any unit declared ``public`` can be used as a sink. To support
  sink behavior additional code is emitted and invoked at runtime, regardless
  of whether the unit is used as a sink or not.

  We now detect unused sink functionality and avoid emitting it.

- GH-934: Allow ``$$`` in place of ``self`` in unit convert attributes.

.. rubric:: Changed Functionality

- GH-941: Allow use of units with all defaulted parameters as entry points.

- We added precompilation support for ``libspicy.h``.

- Drop support for end-of-life Fedora 32, and add support for Fedora 34.

.. rubric:: Bug fixes

- Correctly handle lookups for NULL library symbols.

- Use safe integers for ``size`` functions in the runtime library.

- Make it possible to build on ARM64.

- Fix building with gcc-11.

.. rubric:: Documentation

Version 1.2
===========

.. rubric:: New Functionality

- GH-913: Add support for switch-level ``&parse-at`` and
  ``&parse-from`` attributes inside a unit.

- Add optimizer pass removing unimplemented functions and methods.

  This introduces a global pass triggered after all individual input ASTs have
  been finalized, but before we generate any C++ code. We then strip out any
  unimplemented member functions (typically Spicy hooks), both their
  definitions as well as their uses.

  In order to correctly handle previously generated C++ files which might
  have been generated with different optimization settings, we disallow
  optimizations if we detect that a C++ input file was generated by us.

.. rubric:: Changed Functionality

- Add validation of unit switch attributes. We previously silently
  ignored unsupported attributes; now errors are raised.

- Remove configure option ``--build-zeek-plugin``. Spicy no longer
  supports building the Zeek plugin/analyzers in-tree. This used to be
  available primarily for development purposes, but became challenging
  to maintain.

- Add environment variable ``HILTI_CXX_INCLUDE_DIRS`` to specify
  additional C++ include directories when compiling generated code.

- GH-940: Add runtime check for parsing progress during loops.

.. rubric:: Bug fixes

- Fix computation of unset locations.

- Fix accidental truncating conversion in integer code.

.. rubric:: Documentation

Version 1.1
===========

.. rubric:: New Functionality

- GH-844: Add support for ``&size`` attribute to unit ``switch``
  statement.

- GH-26: Add ``%skip``, ``%skip-pre`` and ``%skip-post`` properties
  for skipping input matching a regular expression before any further
  input processing takes place.

- Extend library functionality provided by the ``spicy`` module:

   - ``crc32_init()/crc32_add()`` compute CRC32 checksums.
   - ``mktime()`` creates a ``time`` value from individual components.
   - ``zlib_init()`` initializes a ``ZlibStream`` with a given window bits argument.
   - ``Zlib`` now accepts a window bits parameter.

- Add a new ``find()`` method to units for that searches for a
  ``bytes`` sequence inside their input data, forward or backward
  from a given starting position.

- Add support for ``&chunked`` when parsing bytes data with
  ``&until`` or ``&until_including``.

- Add ``encode()`` method to ``string`` for conversion to ``bytes``.

- Extend parsing of ``void`` fields:

   - Add support for ``&eod`` to skip all data until the end of the
     current input is encountered.

   - Add support for ``&until`` to skip all data until a deliminator
     is encountered. The deliminator will be extracted from the stream
     before continuing.

- Port Spicy to Apple silicon.

- Add Dockerfile for OpenSUSE 15.2.

.. rubric:: Changed Functionality

- Reject ``void`` fields with names.
- Lower minimum required Python version to 3.2.
- GH-882: Lower minimum required Bison version to 3.0.

.. rubric:: Bug fixes

- GH-872: Fix missing normalization of enum label IDs.
- GH-878: Fix casting integers to enums.
- GH-889: Fix hook handling for anonymous void fields.
- GH-901: Fix type resolution bug in ``&convert``.
- Fix handling of ``&size`` attribute for anonymous void fields.
- Fix missing update to input position before running ``%done`` hook.
- Add validation rejecting ``$$`` in hooks not supporting it.
- Make sure container sizes are runtime integers.
- Fix missing operator<< for enums when generating debug code.
- GH-917: Default-initialize forwarding fields without type arguments.
- GH-1774: Fix synchronization with symbol different from last lookahead token.
- GH-1777: Fix interning of regexps for ``%skip*``.

.. rubric:: Documentation

- GH-37: Add documentation on how to skip data with ``void`` fields.
