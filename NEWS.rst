This following summarizes the most important changes in recent Spicy releases.
For an exhaustive list of all changes, see the :repo:`CHANGES` file coming with
the distribution.

Version 1.7 (in progress)
=========================

.. rubric:: New Functionality

.. rubric:: Changed Functionality

.. rubric:: Bug fixes

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

  .. code-block:: ruby

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

- GH-1183: Update docs for Discourse migration [skip CI].

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

.. rubric:: Documentation

- GH-37: Add documentation on how to skip data with ``void`` fields.
