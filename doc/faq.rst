
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

Depending on the complexity of the Spicy code, processing through
``spicyc``/``spicyz``/``spicy-driver`` may take a bit. The bulk of the
time time tends to be spent on compiling the generated C++ code; often
about 80-90%. Make sure to run :ref:`spicy-precompile-headers
<parser-development-setup>` to speed that up a little. During
development of new parsers, it also helps quite a bit to build
non-optimized debug versions by adding ``--debug`` to the
command-line.

If you want to see a break-down of where Spicy spends its time, run
the tools with ``--report-times``. (In the output at the end, ``jit``
refers to compiling generated C++ code).

Zeek
----

.. _faq_zeek_install_spicy_and_plugin_to_use_parsers:

.. rubric:: Do I need to install Spicy and its Zeek plugin to use Spicy parsers in Zeek?

As of version 5.0 Zeek by default bundles Spicy and its Zeek plugin. If that is
the case the folder containing the ``zeek`` binary should also contain e.g.,
``spicyc`` (provided by Spicy) and ``spicyz`` (provided by Spicy plugin). To
check that the Spicy plugin is active look for ``Zeek::Spicy`` in the output
of ``zeek -N``::

    # zeek -N
    <...>
    Zeek::Spicy - Support for Spicy parsers (``*.spicy``, ``*.evt``, ``*.hlto``) (built-in)

If ``spicyc`` is missing, you need to :ref:`install Spicy <installation>`; if
``spicyz`` is missing or ``Zeek::Spicy`` is not listed you need to :ref:`install
Spicy plugin <zeek_spicy_plugin_installation>`.

.. _faq_zeek_install_spicy_to_use_plugin:

.. rubric:: Do I need a Spicy installation for using the Zeek plugin?

No, if the Zeek plugin was compiled with ``--build-toolchain=no``,
it will not require Spicy to be installed on the system. It will only
be able to load pre-compiled analyzers then (i.e., ``*.hlto`` files),
which you can create on a similar system that has Spicy installed
through :ref:`spicyz <spicyz>`. The build process will leave a binary
distribution inside your build directory at
``zeek/plugin/Zeek_Spicy.tgz``.

.. _faq_zeek_spicy_dpd_support:

.. rubric:: Does Spicy support *Dynamic Protocol Detection (DPD)*?

Yes, see the :ref:`corresponding section <zeek_dpd>` on how to add it
to your analyzers.

.. _faq_zeek_layer2_analyzer:

.. rubric:: Can I write a Layer 2 protocol analyzer with Spicy?

Yes, you can. In Zeek terminology a layer 2 protocol analyzer is a packet
analyzer, see the :ref:`corresponding section <zeek_packet_analyzer>` on how
to declare such an analyzer.

.. _faq_zeek_print_statements_no_effect:

.. rubric:: I have ``print`` statements in my Spicy grammar, why do I not see any output when running Zeek?

The Zeek plugin by default disables the output of Spicy-side ``print``
statements. To enable them, add ``Spicy::enable_print=T`` to the Zeek
command line (or ``redef Spicy::enable_print=T;`` to a Zeek script
that you are loading).

.. _faq_zeek_tcp_analyzer_not_all_messages_recognized:

.. rubric:: My analyzer recognizes only one or two TCP packets even though there are more in the input.

The Zeek Spicy plugin parses the sending and receiving sides of a TCP
connection each according to the given Spicy grammar. This means that
if more than one message can be sent per side the grammar needs to
allow for that. For example, if the grammar parses messages of the
protocol as ``Message``, the top-level parsing unit given in the EVT
file needs to be able to parse a list of messages ``Message[]``.

A simple way to accomplish this is to introduce a parser which wraps
messages of the protocol:

.. code-block:: spicy

   type Message = unit {
     # Fields for messages of the protocol.
   };

   # Parser used e.g., in EVT file.
   public type Messages = unit {
     messages: Message[];
   };
