
.. _faq:

==========================
Frequently Asked Questions
==========================

Zeek
----

.. rubric:: Do I need a Spicy installation for using the Zeek plugin?

No, if the Zeek plugin was compiled with ``--disable-jit-for-zeek``,
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
