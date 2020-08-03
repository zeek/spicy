
.. _toolchain:

=========
Toolchain
=========

.. _spicy-build:

``spicy-build``
===============

``spicy-build`` is a shell frontend that compiles Spicy source code
into a standalone executable by running :ref:`spicyc` to generate the
necessary C++ code, then spawning the system compiler to compile and
link that.

.. spicy-output:: usage-spicy-build
    :exec: spicy-build -h

.. _spicy-config:

``spicy-config``
================

``spicy-config`` reports information about Spicy's build &
installation options.

.. spicy-output:: usage-spicy-config
    :exec: spicy-config -h

.. _spicyc:

``spicyc``
==========

``spicyc`` compiles Spicy code into C++ output, optionally also
executing it directly through JIT.

.. spicy-output:: usage-spicyc
    :exec: spicyc -h

.. _spicy-driver:

``spicy-driver``
================

``spicy-driver`` is a standalone Spicy host application that compiles
and executes Spicy parsers on the fly, and then feeds them data for
parsing from standard input.

.. spicy-output:: usage-spicy-driver
    :exec: spicy-driver -h

Specifying the parser to use
----------------------------

If there's only single ``public`` unit in the Spicy source code,
``spicy-driver`` will automatically use that for parsing its input. If
there's more than one public unit, you need to tell ``spicy-driver``
which one to use through its ``--parser`` (or ``-p``) option. To see
the parsers that are available, use ``--list-parsers`` (or ``-l``).

In addition to the names shown by ``--list-parsers``, you can also
specify a parser through a port or MIME type if the corresponding unit
:ref:`defines them through properties <unit_meta_data>`. For example,
if a unit defines ``%port = 80/tcp``, you can use ``spicy-drver -p
80/tcp`` to select it. If it defines ``%mime-type =
application/test``, you can select it through ``spicy-driver -p
application/test``. Note that there must be exactly one unit with a
matching property for this to work.

Batch input
-----------

``spicy-driver`` provides a batch input mode for processing multiple
interleaved input streams in parallel, mimicking how host applications
like Zeek would be employing Spicy parsers for processing many
sessions concurrently. The batch input must be prepared in a specific
format (see below) that provides embedded meta information about the
contained streams of input. The easiest way to generate such a batch
is :download:`a Zeek script coming with Spicy
</_static/record-spicy-batch.zeek>`. If you run Zeek with this script
on a PCAP trace, it will record the contained TCP and UDP sessions
into a Spicy batch file::

    # zeek -b -r http/methods.trace record-spicy-batch.zeek
    tracking [orig_h=128.2.6.136, orig_p=46562/tcp, resp_h=173.194.75.103, resp_p=80/tcp]
    tracking [orig_h=128.2.6.136, orig_p=46563/tcp, resp_h=173.194.75.103, resp_p=80/tcp]
    tracking [orig_h=128.2.6.136, orig_p=46564/tcp, resp_h=173.194.75.103, resp_p=80/tcp]
    tracking [orig_h=128.2.6.136, orig_p=46565/tcp, resp_h=173.194.75.103, resp_p=80/tcp]
    tracking [orig_h=128.2.6.136, orig_p=46566/tcp, resp_h=173.194.75.103, resp_p=80/tcp]
    tracking [orig_h=128.2.6.136, orig_p=46567/tcp, resp_h=173.194.75.103, resp_p=80/tcp]
    [...]
    tracking [orig_h=128.2.6.136, orig_p=46608/tcp, resp_h=173.194.75.103, resp_p=80/tcp]
    tracking [orig_h=128.2.6.136, orig_p=46609/tcp, resp_h=173.194.75.103, resp_p=80/tcp]
    tracking [orig_h=128.2.6.136, orig_p=46610/tcp, resp_h=173.194.75.103, resp_p=80/tcp]
    recorded 49 sessions total
    output in batch.dat

You will now have a file ``batch.dat`` that you can use with
``spicy-driver -F batch.data ...``.

The batch created by the Zeek script will select parsers for the
contained sessions through well-known ports. That means your units
need to have a ``%port`` property matching the responder port of the
sessions you want them to parse. So for the HTTP trace above, our
Spicy source code would need to provide a public unit with property
``%port = 80/tcp;``.

In case you want to create batches yourself, we document the batch
format in the following. A batch needs to start with a line
``!spicy-batch v1<NL>``, followed by lines with commands of the form
``@<tag> <arguments><NL>``. All commands refer to a stream of input
through a unique, free-form ID. The following commands are supported:

``@begin ID TYPE PARSER<NL>``
    Initializes a new input stream for parsing, associating the unique
    ID ``ID`` with it. ``TYPE`` must be either ``stream`` for
    stream-based parsing (think: TCP), or ``block`` for parsing each
    data block independent of others (think: UDP). ``PARSER`` is the
    name of the Spicy parser to use for parsing this input stream,
    given in the same form as with ``spicy-driver``'s ``--parser``
    option (i.e., either as a unit name, a ``%port``, or a
    ``%mime-type``).

``@data ID SIZE<NL>``
    A block of data for the input stream ``ID``. This command must be
    followed directly by binary data of length ``SIZE``, plus a final
    newline character. The data represents the next chunk of input for
    the corresponding parsing stream. ``@data`` can be used only
    inside corresponding ``@start`` and ``@end`` commands bracketing
    it.

``@end ID<NL>``
    Finalizes parsing of the input stream associated with ``ID``,
    releasing all state. This must come only after a corresponding
    ``@begin`` command, and every ``@begin`` must eventually be
    followed by an ``@end``.

.. _spicy-dump:

``spicy-dump``
==============

``spicy-dump`` is a standalone Spicy host application that compiles
and executes Spicy parsers on the fly, feeds them data for proessing,
and then at the end prints out the parsed information in either a
readable, custom ASCII format, or as JSON (``--json`` or ``-J``). By
default, ``spicy-dump`` disables showing the output of Spicy ``print``
statements, ``--enable-print`` or ``-P`` reenables that.

.. spicy-output:: usage-spicy-dump
    :exec: spicy-dump -h
