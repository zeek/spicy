
.. _faq:

==========================
Frequently Asked Questions
==========================

Spicy Language
--------------

.. rubric:: Are Spicy's global variables *really* global?

Indeed, they are. Changes to global variables become visible to all
Spicy code; their values are not associated with specific connections
or other dynamic state. If they are public, they can even be accessed
from other, unrelated modules as well. This all means that globals
often won't be the right tool for the job; it's rare that a parser
needs truly global state. Take a look at :ref:`unit_context` for a
different mechanism tying state to the current connection, which is a
much more common requirement.

Toolchain
---------

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

.. rubric:: Do I need a Spicy installation for using the Zeek plugin?

No, if the Zeek plugin was compiled with ``--build-toolchain=no``,
it will not require Spicy to be installed on the system. It will only
be able to load pre-compiled analyzers then (i.e., ``*.hlto`` files),
which you can create on a similar system that has Spicy installed
through :ref:`spicyz <spicyz>`. The build process will leave a binary
distribution inside your build directory at
``zeek/plugin/Zeek_Spicy.tgz``.

.. rubric:: Does Spicy support *Dynamic Protocol Detection (DPD)*?

Yes, see the :ref:`corresponding section <zeek_dpd>` on how to add it
to your analyzers.

.. rubric:: I have ``print`` statements in my Spicy grammar, why do I not see any output when running Zeek?

The Zeek plugin by default disables the output of Spicy-side ``print``
statements. To enable them, add ``Spicy::enable_print=T`` to the Zeek
command line (or ``redef Spicy::enable_print=T;`` to a Zeek script
that you are loading).

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
