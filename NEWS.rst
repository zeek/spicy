
This following summarizes the most important changes in recent Spicy
releases. For an exhaustive list of all changes, see the `CHANGES
<https://github.com/zeek/spicy/blob/main/CHANGES>`_ file coming with
the distribution.

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
