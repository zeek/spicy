
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

``spicyc`` also supports the following environment variables to
control the compilation process:

	``SPICY_PATH``
        Replaces the built-in search path for `*.spicy` source files.

    ``SPICY_CACHE``
        Location for storing precompiled C++ headers. Default is ``~/.cache/spicy/<VERSION>``.

    ``HILTI_CXX``
        Specifies the path to the C++ compiler to use.

    ``HILTI_CXX_COMPILER_LAUNCHER``
        Specifies a command to prefix compiler invocations with during JIT.
        This can e.g., be used to use a compiler cache like
        `ccache <https://ccache.dev/>`_. If Spicy was configured with e.g.,
        ``--with-hilti-compiler-launcher=ccache`` (the equivalent CMake option
        is ``HILTI_COMPILER_LAUNCHER``) ``ccache`` would automatically be used
        during JIT. Setting this variable to an empty value disables use of
        ``ccache`` in that case.

    ``HILTI_CXX_FLAGS``
        Specifies additional flags to pass during C++ compilation. This will be
        added after all implicit arguments. Use ``HILTI_CXX_INCLUDE_DIRS`` to
        specify additional include directories.

    ``HILTI_CXX_INCLUDE_DIRS``
        Specifies additional, colon-separated C++ include directories to
        search for header files. Directories passed via
        ``HILTI_CXX_INCLUDE_DIRS`` will be searched for headers before any
        header search paths implicit in Spicy C++ compilation.

    ``HILTI_JIT_PARALLELISM``
        Set to specify the maximum number of background compilation jobs to run
        during JIT. Defaults to number of cores.

    ``HILTI_JIT_SEQUENTIAL``
        Set to prevent spawning multiple concurrent C++ compiler instances.
        This overrides any value set for ``HILTI_JIT_PARALLELISM`` and
        effectively sets it to one.

    ``HILTI_OPTIMIZER_PASSES``
        Colon-separated list of optimizer passes to activate. If unset uses the
        default-enabled set.

    ``HILTI_PATH``
        Replaces the built-in search path for `*.hlt` source files.

    ``HILTI_PRINT_SETTINGS``
        Set to see summary of compilation options.

    ``HILTI_OPTIMIZER_ENABLE_CFG``
        Set to anything but `1` to disable control-flow based optimizations.
        These optimizations remove dead code both in user as well as in
        Spicy-generated code, so enabling these optimizations can improve
        runtime parser throughput as well as lead to faster faster C++
        compilation.

.. _spicy-driver:

``spicy-driver``
================

``spicy-driver`` is a standalone Spicy host application that compiles
and executes Spicy parsers on the fly, and then feeds them data for
parsing from standard input.

.. spicy-output:: usage-spicy-driver
    :exec: spicy-driver -h

``spicy-driver`` supports the same environment variables as
:ref:`spicyc`.

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
if a unit defines ``%port = 80/tcp``, you can use ``spicy-driver -p
80/tcp`` to select it. To specify a direction, add either ``%orig`` or
``%resp`` (e.g., ``-p 80/tcp%resp``); then only units with a port
tagged with an ``&originator`` or ``&responder`` attribute,
respectively, will be considered. If a unit defines ``%mime-type =
application/test``, you can select it through ``spicy-driver -p
application/test``.

.. versionadded:: 1.13 Verbose mode for ``list-parsers``

Internally, these port-based arguments for ``-p`` are alias names for
existing parsers. You can see all aliases by running ``spicy-driver``
with ``-ll`` (i.e., ``--list-parsers`` twice).

.. _spicy-driver-batch:

Batch input
-----------

``spicy-driver`` provides a batch input mode for processing multiple
interleaved input flows in parallel, mimicking how host applications
like Zeek would be employing Spicy parsers for processing many
sessions concurrently. The batch input must be prepared in a specific
format (see below) that provides embedded meta information about the
contained flows of input. If you have Zeek at hand, the easiest way to
generate such a batch is `a script coming with Zeek
<https://github.com/zeek/zeek/blob/master/scripts/policy/frameworks/spicy/record-spicy-batch.zeek>`_.
If you run Zeek with this script on a PCAP trace, it will record the
contained TCP and UDP sessions
into a Spicy batch file::

    # zeek -b -r http/methods.trace policy/frameworks/spicy/record-spicy-batch
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

By default, the batch created by the Zeek script will select parsers for the
contained sessions through well-known ports. That means your units
need to have a ``%port`` property matching the responder port of the
sessions you want them to parse. So for the HTTP trace above, our
Spicy source code would need to provide a public unit with property
``%port = 80/tcp;``.

.. versionadded:: 1.13 ``--parser-alias``

Alternatively, you can run ``spicy-driver`` with ``--parser-alias
PORT=PARSER`` to tell it explicitly which parsers to use for
connections on a particular port. Here, ``PORT`` must be of the form
``<port>/<protocol>`` (e.g., ``80/tcp``), and ``PARSER`` is the name
of the parser to use (as shown by ``spicy-driver --list-parsers``). By
default, the parser will be applied to both directions of all
connections that are using that responder port. You can limit the
direction by appending either ``%orig`` or ``%resp`` to ``PORT``
(e.g., ``80/tcp%orig`` to attach the parser only to originator-side
flows). ``--parser-alias`` can be used multiple times to specify
further mappings.

In case you want to create batches yourself, we document the batch
format in the following. A batch needs to start with a line
``!spicy-batch v2<NL>``, followed by lines with commands of the form
``@<tag> <arguments><NL>``.

There are two types of input that the batch format can represent: (1)
individual, uni-directional flows; and (2) bi-directional connections
consisting in turn of one flow per side. The type is determined
through an initial command: ``@begin-flow`` starts a flow flow, and
``@begin-conn`` starts a connection. Either form introduces a unique,
free-form ID that subsequent commands will then refer to. The
following commands are supported:

``@begin-flow FID TYPE PARSER<NL>``
    Initializes a new input flow for parsing, associating the unique
    ID ``FID`` with it. ``TYPE`` must be either ``stream`` for
    stream-based parsing (think: TCP), or ``block`` for parsing each
    data block independent of others (think: UDP). ``PARSER`` is the
    name of the Spicy parser to use for parsing this input flow,
    given in the same form as with ``spicy-driver``'s ``--parser``
    option (i.e., either as a unit name, a ``%port``, or a
    ``%mime-type``).

``@begin-conn CID TYPE ORIG_FID ORIG_PARSER RESP_FID RESP_PARSER<NL>``
    Initializes a new input connection for parsing, associating the
    unique connection ID ``CID`` with it. ``TYPE`` must be either
    ``stream`` for stream-based parsing (think: TCP), or ``block`` for
    parsing each data block independent of others (think: UDP).
    ``ORIG_FID`` is separate unique ID for the originator-side flow,
    and ``ORIG_PARSER`` is the name of the Spicy parser to use for
    parsing that flow. ``RESP_FID`` and ``RESP_PARSER`` work
    accordingly for the responder-side flow. The parsers can be given
    in the same form as with ``spicy-driver``'s ``--parser`` option
    (i.e., either as a unit name, a ``%port``, or a ``%mime-type``).

``@data FID SIZE<NL>``
    A block of data for the input flow ``FID``. This command must be
    followed directly by binary data of length ``SIZE``, plus a final
    newline character. The data represents the next chunk of input for
    the corresponding flow. ``@data`` can be used only inside
    corresponding ``@begin-*`` and ``@end-*`` commands bracketing the
    flow ID.

``@gap FID SIZE<NL>``
    A gap of size ``SIZE``. This inserts a gap into the input stream
    that will trigger a parse error once the parser reaches it. If the
    parser supports error recovery, it will then attempt to continue
    processing after the gap. ``@gap`` is similar to how a host
    application like Zeek would report TCP reassembly gaps caused by
    missing packets.

``@end-flow FID<NL>``
    Finalizes parsing of the input flow associated with ``FID``,
    releasing all state. This must come only after a corresponding
    ``@begin-flow`` command, and every ``@begin-flow`` must eventually
    be followed by an ``@end-flow``.

``@end-conn CID<NL>``
    Finalizes parsing the input connection associated with ``CID``,
    releasing all state (including for its two flows). This must come
    only after a corresponding ``@begin-conn`` command, and every
    ``@begin-conn`` must eventually be followed by an ``@end-end``.

.. _spicy-dump:

``spicy-dump``
==============

``spicy-dump`` is a standalone Spicy host application that compiles
and executes Spicy parsers on the fly, feeds them data for processing,
and then at the end prints out the parsed information in either a
readable, custom ASCII format, or as JSON (``--json`` or ``-J``). By
default, ``spicy-dump`` disables showing the output of Spicy ``print``
statements, ``--enable-print`` or ``-P`` reenables that.

.. spicy-output:: usage-spicy-dump
    :exec: spicy-dump -h
