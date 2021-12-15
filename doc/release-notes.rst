=============
Release Notes
=============

.. include:: /../NEWS.rst

Migrating from the old prototype
================================

Below we summarize language changes in Spicy compared to the `original
research prototype <https://www.icir.org/hilti>`_. Note that some of
the prototype's more advanced functionality has not yet been ported to
the new code base; see the `corresponding list
<https://github.com/zeek/spicy/issues?q=is%3Aissue+is%3Aopen+label%3A%22Port+V1%22>`_
on GitHub for what's still missing.

Changes:

- Renamed ``export`` linkage to ``public``.

- Renamed ``%byteorder`` property to ``%byte-order``.

- Renamed ``&byteorder`` attribute to ``&byte-order``.

- Renamed ``&bitorder`` attribute to ``&bit-order``.

- All unit-level properties now need to conclude with a semicolon (e.g.,
  ``%filter;``).

- Renamed ``&length`` attribute to ``&size``.

- Renamed ``&until_including`` attribute to ``&until-including``.

- Replaced ``&parse`` with separate ``&parse-from`` (taking a "bytes"
  instance) and ``&parse-at`` (taking a stream iterator) attributes.

- Attributes no longer accept their arguments in parentheses, it now
  must ``<attr>=expr``. (Before, both versions were accepted.)

- ``uint<N>`` and ``int<N>`` are no longer accepted, use
  ``uintN/intN`` instead (which worked before already as well)

- ``list<T>`` is no longer supported, use ``vector<T>`` instead.

- New syntax for parsing sequences: Use ``x: int8[5]`` instead of ``x:
  vector<int8> &length=5``. For lists of unknown size, use ``x:
  int8[]``. When parsing sequences sub-units, use: ``x: Item[]``; or,
  if further arguments/attributes are required, ``x:
  (Item(1,2,3))[]``. (The latter syntax isn't great, but the old
  syntax was ambiguous.)

- New syntax for functions: ``function f(<params>) [: <result>]``
  instead of ``<result> f(<params>)``

- Renamed runtime support module from ``Spicy`` to ``spicy`` (so use
  ``import spicy``)

- In units, variables are now initialized to default values by
  default. Previously, that was (inconsistently) happening only for
  variables of type sink. To revert to the old behaviour, add
  "&optional" to the variable.

- Renamed type ``double`` to ``real``.

- Generally, types don't coerce implicitly to bool anymore except in
  specific language contexts, such as in statements with boolean
  conditions.

- Filters can now be implemented in Spicy itself. The pre-built
  ``filter::Base64Decode`` and ``filter::Zlib`` provide the base64 and
  zlib functionality of the previously built-in filters.

- ``{unit,sink}::add_filter`` are renamed to ``{unit,sink}::connect_filter``.

- Enums don't coerce to bool anymore, need to manually compare to
  ``Undef``.

- Coercion to bool now happens only in certain contexts, like
  ``if``-conditions (similar to C++).

- The sink method ``sequence`` has been renamed to
  ``sequence_number``.

- The effect of the sink method ``set_initial_sequence_number`` no
  longer persists when reconnecting a different unit to a sink.

- ``&transient`` is no longer a supported unit field attribute. The
  same effect can now be achieved through an anonymous field (also see
  next point).

- ``$$`` can now be generally used in hooks to refer to the just
  parsed value. That's particularly useful inside hooks for anonymous
  fields, including fields that previously were ``&transient`` (see
  above). Previously, "$$" worked only for container elements in
  ``foreach`` hooks (which still operates the same way).

- Fields of type ``real`` are parsed with ``&type`` attribute (e.g.,
  ``&type=Spicy::RealType::IEEE754_Double``). They used to
  ``&precision`` attributes with a different enum type.

- Assigning to unit fields and variables no longer triggers any hooks.
  That also means that hooks are generally no longer supported for
  variables (This is tricky to implement, not clear it's worth the
  effort.)

- When importing modules, module names are now case-sensitive.

- When parsing vectors/lists of integers of a given length, use
  ``&count`` instead of ``&length``.

- Zeek plugin:

    - ``Bro::dpd_confirm()`` has been renamed to
      ``zeek::confirm_protocol()``. There's also a corresponding
      ``zeek::reject_protocol()``.

    - To auto-export enums to Zeek, they need to be declared public.
