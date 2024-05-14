
.. _faq:

==========================
Frequently Asked Questions
==========================

Spicy Language
--------------

.. _faq_spicy_global_variables:

.. rubric:: Are Spicy's global variables *really* global?

Indeed, they are. Changes to global variables become visible to all
Spicy code; their values are not associated with specific connections
or other dynamic state. If they are public, they can even be accessed
from other, unrelated modules as well. This all means that globals
often won't be the right tool for the job; it's rare that a parser
needs truly global state. Take a look at :ref:`unit_context` for a
different mechanism tying state to the current connection, which is a
much more common requirement.

.. _faq_spicy_line_numbers:

.. rubric:: What do the numbers in ``foo.spicy:37:1`` or
  ``foo.spicy:37:1-42:19`` in messages mean?

These are source locations or source ranges. You might encounter them in e.g.,
error messages from the Spicy compiler or in errors when parsing fails.

In this case ``foo.spicy:37:1`` is a source location, in particular it refers
to line 37, character 1 in the file ``foo.spicy``; ``foo.spicy:37:1-42:19`` is
a source range in the file ``foo.spicy`` starting in line 37, character 1 and
ending in line 42, character 19 in the same file.

Toolchain
---------

.. _faq_toolchain_speed_up_compilation:

.. rubric:: Is there a way to speed up compilation of Spicy code?

Please see :ref:`performance_toolchain`.

Zeek
----

See Zeek's Spicy FAQ :zeek:`devel/spicy/faq.html`.
