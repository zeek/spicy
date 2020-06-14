
.. _zeek:

================
Zeek Integration
================

While Spicy itself remains application independent, transparent
integration into Zeek has been a primary goal for its development. To
facilitate adding new protocol and file analyzers to Zeek, Spicy ships
with a Zeek plugin that makes its parsers accessible to Zeek's
processing pipeline. In the following, we dig deeper into how to use
all of this.

.. _zeek_terminology:

Terminology
===========

In Zeek, the term "analyzer" refers generally to a component that
processes a particular protocol ("protocol analyzer") or file format
("file analyzer"). "Processing" here is more than just parsing
content: An analyzer controls when it wants to be used (e.g., with
connection on specific ports, or with files of a specific MIME type);
what events to generate for Zeek's scripting layer; and how to handle
any errors occurring during parsing. While Spicy itself focuses just
on the parsing part, the Spicy plugin provides the remaining pieces to
Zeek, turning a Spicy parser into a full Zeek analyzer. That's what we
refer to as "Spicy (protocol or file) analyzer" for Zeek.

.. _zeek_installation:

Installation
============

To use the Spicy plugin with Zeek, the main preparation task is making
sure Zeek knows where to find it. If you performed a standard Spicy
installation through ``make install``, that will normally have linked
the plugin right into Zeek's system-wide plugin directory so that it
becomes directly available. You can check the output of ``zeek -N`` to
confirm::

    # zeek -N Zeek::Spicy
    Zeek::Spicy - Support for Spicy parsers (*.spicy, *.evt, *.hlto) (dynamic, version 0.3.0)

If the symlink didn't get installed (e.g., because you're lacking
permission to write into Zeek's plugin's directory), you can
alternatively set Zeek's ``ZEEK_PLUGIN_PATH`` manually to the
directory where the installation placed the plugin. ``spicy-config
--zeek-plugin-path`` knows where that is::

    # export ZEEK_PLUGIN_PATH=$(spicy-config --zeek-plugin-path)
    # zeek -N Zeek::Spicy
    Zeek::Spicy - Support for Spicy parsers (*.spicy, *.evt, *.hlto) (dynamic, version 0.3.0)

If you want to move the plugin to other systems, you can find a binary
distribution inside your build directory at
``zeek/plugin/Zeek_Spicy.tgz``. If you have built the plugin without
JIT support (``configure --disable-jit-for-zeek ...``), it will not
require a Spicy installation to operate.

.. note::

    Developer's note: You can also point ``ZEEK_PLUGIN_PATH`` to the
    Spicy build directory, without installing it first. The plugin get
    built into ``<build-directory>/zeek/plugin``.

Interface Definitions ("evt files")
===================================

Per above, a Spicy analyzer for Zeek does more than just parsing data.
Accordingly, we need to tell the Zeek plugin a couple of additional
pieces about analyzers we want it to provide to Zeek:

Analyzer setup
    The plugin needs to know what type of analyzers we are creating,
    when we want Zeek to activate them, and what Spicy unit types to
    use as their parsing entry point.

Event definitions
   We need to tell the Spicy plugin what Zeek events to provide and
   when to trigger them.

We define all of these through custom interface definition files that
the Spicy plugin reads in. These files use an ``*.evt`` extension, and
the following subsections discuss their content in more detail.

Generally, empty lines and comments starting with ``#`` are ignored in
an ``*.evt``.

.. note::

    The syntax for ``*.evt`` files comes with some legacy pieces that
    aren't particularly pretty. We may clean that up at some point.

Analyzer Setup
--------------

You can define both protocol analyzers and file analyzers in an
``*.evt`` file, per the following.

.. rubric:: Protocol Analyzer

To define a protocol analyzer, add a new section to an ``*.evt``
file that looks like this::

    protocol analyzer ANALYZER_NAME over TRANSPORT_PROTOCOL:
        PROPERTY_1,
        PROPERTY_2,
        ...
        PROPERTY_N;

Here, ``ANALYZER_NAME`` is a name to identify your analyzer inside
Zeek. You can choose names arbitrarily as long as they are unique. As
a convention, however, we recommend name with a ``spicy::*`` prefix
(e.g., ``spicy::BitTorrent``).

On the Zeek-side, through some normalization, these names
automatically turn into tags added to Zeek's ``Analyzer::Tag`` enum.
For example, ``spicy::BitTorrent`` turns into
``Analyzer::ANALYZER_SPICY_BITTORRENT``.

The analyzer's name is also what goes into Zeek signatures to activate
an analyzer DPD-style. If the name is ``spicy::BitTorrent``, you'd
write ``enable "spicy::BitTorrent"`` into the signature.

.. note::

    Once you have made your analyzers available to Zeek (which we will
    discuss below), running ``zeek -NN Zeek::Spicy`` will show you a
    summary of what's now available, including their Zeek-side names
    and tags.

``TRANSPORT_PROTOCOL`` can be either ``tcp`` or ``udp``, depending on
the transport-layer protocol that your new analyzer wants to sit on
top of.

Following that initial ``protocol analyzer ...`` line, a set of
properties defines further specifics of your analyzer. The following
properties are supported:

    ``parse [originator|responder] with SPICY_UNIT``
        Specifies the top-level Spicy unit(s) the analyzer uses for
        parsing payload, with ``SPICY_UNIT`` being a fully-qualified
        Spicy-side type name (e.g. ``HTTP::Request``). The unit type must
        have been declared as ``public`` in Spicy.

        If ``originator`` is given, the unit is used only for parsing the
        connection's originator-side payload; and if ``responder`` is
        given, only for responder-side payload. If neither is given, it's
        used for both sides. In other words, you can use different units
        per side by specifying two properties ``parse originator with
        ...`` and ``parse responder with ...``.

    ``port PORT`` or ``ports { PORT_1, ..., PORT_M }``
        Specifies one or more well-known ports for which you want Zeek to
        automatically activate your analyzer with corresponding
        connections. Each port must be specified in Spicy's :ref:`syntax
        for port constants <type_port>` (e.g., ``80/tcp``). The ports'
        transport protocol must match that of the analyzer.

        .. todo::

            The plugin should pick up any ``%port`` :ref:`unit_meta_data`,
            but it doesn't yet (:issue:`95`).

    ``replaces ANALYZER_NAME``
        Disables an existing analyzer that Zeek already provides
        internally, allowing you to replace a built-in analyzer with a new
        Spicy version. ``ANALYZER_NAME`` is the Zeek-side name of the
        analyzer. To find that name, inspect the output of ``zeek -NN``
        for available analyzers::

            # zeek -NN | grep '\[Analyzer\]'
            ...
            [Analyzer] SMTP (ANALYZER_SMTP, enabled)
            ...

        Here, ``SMTP`` is the name you would write into ``replaces`` to
        disable the built-in SMTP analyzer.

As a full example, here's what a new HTTP analyzer could look like::

    protocol analyzer spicy::HTTP over TCP:
        parse originator with HTTP::Requests,
        parse responder with HTTP::Replies,
        port 80/tcp,
        replaces HTTP;

.. rubric:: File Analyzer

Defining file analyzers works quite similar to protocol analyzers,
through ``*.evt`` sections like this::

    file analyzer ANALYZER_NAME:
        PROPERTY_1,
        PROPERTY_2,
        ...
        PROPERTY_N;

Here, ``ANALYZER_NAME`` is again a name to identify your analyzer
inside Zeek.  On the Zeek-side, the name will be added to Zeek's
``Files::Tag`` enum.

File analyzers support the following properties:

    ``parse with SPICY_UNIT``
        Specifies the top-level Spicy unit the analyzer uses for
        parsing file content, with ``SPICY_UNIT`` being a
        fully-qualified Spicy-side type name. The unit type must have
        been declared as ``public`` in Spicy.

    ``mime-type MIME-TYPE``
        Specifies a MIME type for which you want Zeek to automatically
        activate your analyzer when it sees a corresponding file on
        the network. The type is a specified in standard
        ``type/subtype`` notion, without quotes (e.g., ``image/gif``).

        .. note::

            Keep in mind that Zeek identifies MIME types through
            "content sniffing" (i.e., similar to libmagic), and
            usually not by protocol-level headers (e.g., *not* through
            HTTP's ``Content-Type`` header). If in doubt, examine
            ``files.log`` for what it records as a file's type.

As a full example, here's what a new GIF analyzer could look like::

    file analyzer spicy::GIF:
        parse with GIF::Image,
        mime-type image/gif;

Event Definitions
-----------------

To define a Zeek event that you want the Spicy plugin to trigger, you
add lines of the form::

    on HOOK_ID -> event EVENT_NAME(ARG1_, ..., ARG_N);

    on HOOK_ID if COND -> event EVENT_NAME(ARG1_, ..., ARG_N);

The Zeek plugin automatically derives from this everything it needs to
register new events with Zeek, including a mapping of the arguments'
Spicy types to corresponding Zeek types. More specifically, these are
the pieces going into such an event definition:

``on HOOK_ID``
    A Spicy-side ID that defines when you want to trigger the event.
    This works just like a ``on ...`` :ref:`unit hook <unit_hooks>`,
    and you can indeed use anything here that Spicy supports for those
    as well (except container hooks). So, e.g., ``on
    HTTP::Request::%done`` triggers an event whenever a
    ``HTTP::Request`` unit has been fully parsed, and ``on
    HTTP::Request::uri`` leads to an event each time the ``uri`` field
    has been parsed. (In the former example, you may skip the
    ``%done`` actually: ``on HTTP::Request`` implicitly adds it.)

``EVENT_NAME``
    The Zeek-side name of event you want to generate, preferably
    including a namespace (e.g., ``http::request``).

``ARG_I``
    An argument to pass to the event, given as an arbitrary Spicy
    expression. The expression will be evaluated within the context of
    the unit that the ``on ...`` triggers on, similar to code running
    inside the body of a corresponding :ref:`unit hook <unit_hooks>`.
    That means the expressions has access to ``self`` for accessing
    the unit instance that's currently being parsed.

    The Spicy type of the expression determines the Zeek-side type of
    the corresponding event parameters. Most Spicy types translate
    over pretty naturally, the following summarizes the translation:

    .. csv-table:: Type Conversion from Spicy to Zeek
        :header: "Spicy Type", "Zeek Type", "Notes"

        ``addr``, ``addr``,
        ``bool``, ``bool``,
        ``enum { ... }``, ``enum { ... }``, [1]
        ``int(8|16|32|64)``, ``int``,
        ``list<T>``, ``vector of T``,
        "``map<V,K>``", "``table[V] of K``",
        ``optional<T>``, ``T``,  [2]
        ``port``, ``port``,
        ``real``, ``double``,
        ``set<T>``, ``set[T]``,
        ``string``, ``string``,
        "``tuple<T_1, ... ,T_N>``", "``record { T1, ..., T_N }``", [3]
        ``uint(8|16|32|64)``, ``count``,
        ``vector<T>``, ``vector of T``,

    .. note::

        [1]
            A corresponding Zeek-side ``enum`` type is automatically
            created.

        [2]
            The optional value must have a value, otherwise a runtime
            exception will be thrown.

        [3]
            Must be mapped to a Zeek-side record type with matching
            fields.

            If a tuple element is mapped to a record field with a
            ``&default`` or ``&optional`` attribute, a couple special
            cases are supported:

                - If the expression evaluates to ``Null``, the record
                  field is left unset.

                - If the element's expression uses the
                  :spicy:op:`.? <unit::TryMember>` operator and that
                  fails to produce a value, the record field is
                  likewise left unset.

    In addition to full Spicy expressions, there are three reserved
    IDs with specific meanings when used as arguments:

        ``$conn``
            Refers to the connection that's currently being processed
            by Zeek. On the Zeek-side this will turn into a parameter
            of Zeek type ``connection``. This ID can be used only with
            protocol analyzers.

        ``$file``
            Refers to the file that's currently being processed by
            Zeek. On the Zeek-side this will turn into a parameter of
            Zeek type ``fa_file``. This ID can be used only with file
            analyzers.

        ``$is_orig``
            A boolean indicating if the data currently being processed
            is coming from the originator (``True``) or responder
            (``False``) of the underlying connection. This turns into
            a corresponding boolean value on the Zeek side. This ID
            can be used only with protocol analyzers.

    .. note::

        Some tips:

        - If you want to force a specific type on the Zeek-side, you
          have a couple of options:

            1. Spicy may provide a ``cast`` operator from the actual
               type into the desired type (e.g., ``cast<uint64>(..)``).

            2. Argument expressions have access to global functions
               defined in the Spicy source files, so you can write a
               conversion function taking an argument with its
               original type and returning it with the desired type.

        - List comprehension can be convenient to fill Zeek vectors:
          ``[some_func(i) for i in self.my_list]``.

``if COND``
    If given, events are only generated if the expression ``COND``
    evaluates to true. Just like event arguments, the expression is
    evaluated in the context of the current unit instance and has
    access to ``self``.

Importing Spicy Modules
-----------------------

Code in an ``*.evt`` file may need access to additional Spicy modules,
such as when expressions for event parameters call Spicy
functions defined elsewhere. To make a Spicy module available, you can
insert ``import`` statements into the ``*.evt`` file that work
:ref:`just like in Spicy code <modules_import>`:

    ``import NAME``
        Imports Spicy module ``NAME``.

    ``import NAME from X.Y.Z;``
        Searches for the module ``NAME`` (i.e., for the filename
        ``NAME.spicy``) inside a sub-directory ``X/Y/Z`` along the
        search path, and then imports it.

.. _zeek_compiling:

Compiling Analyzers
====================

Once you have the ``*.spicy`` and ``*.evt`` source files for your new
analyzer, you have two options to compile them, either just-in-time at
startup or in advance.

Just In Time Compilation
------------------------

To compile analyzers on the fly, you just pass your ``*.spicy`` and
``*.evt`` files to Zeek just like any of its scripts, either on the
command-line or through ``@load`` statements. The Spicy plugin hooks
into Zeek's processing of input files and diverts them the right way
into its compilation pipeline.

This approach can be quite convenient, in particular during
development of new analyzers as it makes it easy to iterate---just
restart Zeek to pick up any changes. The disadvantage is that
compiling Spicy parsers takes a noticeable amount of time, which you'll
incur every time Zeek starts up.

.. _spicyz:

Ahead Of Time Compilation
-------------------------

You can also precompile analyzers into ``*.hlto`` object files
containing their final executable code. To do that, pass the relevant
``*.spicy`` and ``*.evt`` files to ``spicyz``, then have Zeek load the
output. To repeat the :ref:`example <example_zeek_my_http>` from the
*Getting Started* guide::

    # spicyz -o my-http-analyzer.hlto my-http.spicy my-http.evt
    # zeek -Cr request-line.pcap my-http-analyzer.hlto my-http.zeek
    Zeek saw from 127.0.0.1: GET /index.html 1.0

While this approach requires an additional step every time
something changes, starting up Zeek now executes quickly.

Run ``spicyz -h`` to see some additional options it provides, which
are similar to :ref:`spicy-driver`.

.. _zeek_functions:

Controlling Zeek from Spicy
===========================

Spicy grammars can import a provided library module ``zeek`` to gain
access to Zeek-specific functions that call back into Zeek's
processing:

.. include:: /autogen/zeek-functions.spicy

.. _zeek_dpd:

Dynamic Protocol Detection (DPD)
================================

Spicy protocol analyzers support Zeek's *Dynamic Protocol Detection*
(DPD), i.e., analysis independent of any well-known ports. To use that
with your analyzer, add two pieces:

1. A `Zeek signature
   <https://docs.zeek.org/en/current/frameworks/signatures.html>`_ to
   activate your analyzer based on payload patterns. Just like with
   any of Zeek's standard analyzers, a signature can activate a Spicy
   analyzer through the ``enable "<name>"`` keyword. The name of the
   analyzer comes out of the EVT file: it is the ``ANALYZER_NAME``
   with the double colons replaced with an underscore (e.g.,
   ``spicy::HTTP`` turns into ``enable "spicy_HTTP"``.

2. You should call ``zeek::confirm_protocol()`` (see
   :ref:`zeek_functions`) from a hook inside your grammar at a point
   when the parser can be reasonably certain that it is processing the
   expected protocol. Optionally, you may also call
   ``zeek::reject_protocol()`` when you're sure the parser is *not*
   parsing the right protocol (e.g., inside an :ref:`%error
   <on_error>` hook). Doing so will let Zeek stop feeding it more
   data.

.. _zeek_configuration:

Configuration
=============

The Spicy plugin provides a set of script-level options to tune its
behavior, similar to what the :ref:`spicy-driver` provides as
command-line arguments:

.. literalinclude:: /../zeek/plugin/scripts/base/spicy/main.zeek
    :language: bro
    :start-after: doc-start
    :end-before:  doc-end

Note, however, that most of those options affect code generation. It's
usually easier to set them through `spicyz` when precompiling an
analyzer. If you are using Zeek itself to compile an analyzer
just-in-time, keep in mind that any code generation options need to be
in effect at the time the Spicy plugin kicks of the compilation
process. A ``redef`` from another script should work fine, as scripts
are fully processed before compilation starts. However, changing
values from the command-line (via Zeek's ``var=value``) won't be
processed in time due to intricacies of Zeek's timing. To make it
easier to change an option from the command-line, the Spicy plugin
also supports an environment variable ``SPICY_PLUGIN_OPTIONS`` that
accepts a subset of ``spicy-driver`` command-line options in the form
of a string. For example, to compile a debug version of all analyzers,
set ``SPICY_PLUGIN_OPTIONS=-d``. The full set of options is this:

.. code-block:: text

    Supported Zeek-side Spicy options:
      -A             When executing compiled code, abort() instead of throwing HILTI exceptions.
      -B             Include backtraces when reporting unhandled exceptions.
      -C             Dump all generated code to disk for debugging.
      -d             Include debug instrumentation into generated code.
      -D <streams>   Activate compile-time debugging output for given debug streams (comma-separated).
      -O             Build optimized release version of generated code.
      -o <out.hlto>  Save precompiled code into file and exit.
      -R             Report a break-down of compiler's execution time.
      -V             Don't validate ASTs (for debugging only).
      -X <addl>      Implies -d and adds selected additional instrumentation (comma-separated).

To get that usage message, set ``SPICY_PLUGIN_OPTIONS=-h`` when
running Zeek.

Debugging
=========

If Zeek doesn't seem to be doing the right thing with your Spicy
analyzer, there are several ways to debug what's going on. To help
with that, make sure to compile your analyzer with ``spicy::debug=T``
(or ``spicyz -d``, or ``SPICY_PLUGIN_OPTIONS=-d``); and, if possible,
use a debug version of Zeek (i.e., build Zeek with ``./configure
--enable-debug``).

If your analyzer doesn't seem to be active at all, first make sure
Zeek actually knows about it: It should show up in the output of
``zeek -NN Zeek::Spicy``. If it doesn't, you might not being loading
the right ``*.spicy`` or ``*.evt`` files. Also check your ``*.evt`` if
it defines your analyzer correctly.

If Zeek knows about your analyzer and just doesn't seem to activate
it, double-check that ports or MIME types are correct in the ``*.evt``
file. If you're using a signature instead, try a port/MIME type first,
just to make sure it's not a matter of signature mismatches.

If there's nothing obviously wrong with your source files, you can
trace what the plugin is compiling by running ``spicyz`` with ``-D
zeek``. For example, reusing the :ref:`HTTP example
<example_zeek_my_http>` from the *Getting Started* guide::

    # spicyz -D zeek my-http.spicy my-http.evt
    [debug/zeek] Beginning pre-script initialization
    [debug/zeek] Done with pre-script initialization
    [debug/zeek] Beginning post-script initialization
    [debug/zeek] Initializing driver
    [debug/zeek] Loading input file "my-http.spicy"
    [debug/zeek] Loading Spicy file "/home/robin/work/spicy/tests/spicy/doc/my-http.spicy"
    [debug/zeek] Loading input file "my-http.evt"
    [debug/zeek] Loading EVT file "/home/robin/work/spicy/doc/examples/my-http.evt"
    [debug/zeek] Loading events from /home/robin/work/spicy/doc/examples/my-http.evt
    [debug/zeek]   Got protocol analyzer definition for spicy_MyHTTP
    [debug/zeek]   Got event definition for MyHTTP::request_line
    [debug/zeek] Compiling input files
    [debug/zeek]   Running Spicy driver
    [debug/zeek]     Got unit type 'MyHTTP::Version'
    [debug/zeek]     Got unit type 'MyHTTP::RequestLine'
    [debug/zeek]   Adding protocol analyzer 'spicy_MyHTTP'
    [debug/zeek]   Adding Spicy hook 'MyHTTP::RequestLine::0x25_done' for event MyHTTP::request_line
    [debug/zeek]   Done with Spicy driver
    [debug/zeek] Initializing Spicy runtime
    [debug/zeek] Have Spicy protocol analyzer spicy_MyHTTP
    [debug/zeek] Registering Protocol::TCP protocol analyzer spicy_MyHTTP with Zeek
    [debug/zeek]   Scheduling analyzer for port 12345/tcp
    [debug/zeek] Done with post-script initialization

You can see the main pieces in there: The files being loaded, unit
types provided by them, analyzers added to Zeek, and events that get
defined.

.. note::

    We're using ``spicyz`` in the example to precompile the code. You
    can get the same debug output from Zeek itself when JITting the
    inputs, but you'll need to pass the option in through the
    environment by setting ``SPICY_PLUGIN_OPTIONS="-D zeek"``,
    otherwise some parts will be missing. See
    :ref:`zeek_configuration` for more on that.

If that all looks as expected, it's time to turn to the Zeek side and
see what it's doing at runtime. You'll need a debug version of Zeek
for that, as well as a small trace with traffic that you expect your
analyzer to process. Run Zeek with ``-B dpd`` (or ``-B file_analysis``
if you're debugging a file analyzer) on your trace to record the
analyzer activity into ``debug.log``. For example, with the same HTTP
example, we get:

.. code-block:: text
    :linenos:

    # zeek -B dpd -Cr request-line.pcap my-http.spicy my-http.evt
    # cat debug.log
    [dpd] Registering analyzer SPICY_MYHTTP for port 12345/1
    [...[
    [dpd] Available analyzers after zeek_init():
    [...]
    [dpd]     spicy_MyHTTP (enabled)
    [...]
    [dpd] Analyzers by port:
    [dpd]     12345/tcp: SPICY_MYHTTP
    [...]
    [dpd] TCP[5] added child SPICY_MYHTTP[7]
    [dpd] 127.0.0.1:59619 > 127.0.0.1:12345 activated SPICY_MYHTTP analyzer due to port 12345
    [...]
    [dpd] SPICY_MYHTTP[7] DeliverStream(25, T) [GET /index.html HTTP/1.0\x0a]
    [dpd] SPICY_MYHTTP[7] EndOfData(T)
    [dpd] SPICY_MYHTTP[7] EndOfData(F)

The first few lines show that Zeek's analyzer system registers the
analyzer as expected. The subsequent lines show that the analyzer gets
activated for processing the connection in the trace, and that it then
receives the data that we know indeed constitutes its payload, before
it eventually gets shutdown.

To see this from the plugin's side at runtime, set the ``zeek`` debug
stream through the ``HILTI_DEBUG`` environment variable::

    # HILTI_DEBUG=zeek SPICY_PLUGIN_OPTIONS="-d" zeek -Cr request-line.pcap my-http.spicy my-http.evt
    [zeek] Have Spicy protocol analyzer spicy_MyHTTP
    [zeek] Registering Protocol::TCP protocol analyzer spicy_MyHTTP with Zeek
    [zeek]   Scheduling analyzer for port 12345/tcp
    [zeek] Done with post-script initialization
    [zeek] [SPICY_MYHTTP/7/orig] initial chunk: |GET /index.html HTTP/1.0\\x0a| (eod=false)
    [zeek] [SPICY_MYHTTP/7/orig] -> event MyHTTP::request_line($conn, GET, /index.html, 1.0)
    [zeek] [SPICY_MYHTTP/7/orig] done with parsing
    [zeek] [SPICY_MYHTTP/7/orig] parsing finished, skipping further originator payload
    [zeek] [SPICY_MYHTTP/7/resp] no unit specificed for parsing
    [zeek] [SPICY_MYHTTP/7/orig] skipping end-of-data delivery
    [zeek] [SPICY_MYHTTP/7/resp] no unit specificed for parsing
    [zeek] [SPICY_MYHTTP/7/orig] skipping end-of-data delivery
    [zeek] [SPICY_MYHTTP/7/resp] no unit specificed for parsing

After the initial initialization, you see the data arriving and the
event being generated for Zeek. The plugin also reports that we didn't
define a unit for the responder side---which we know in this case, but
if that appears unexpectedly you probably found a problem.

.. note::

    If you're running Zeek with ``SPICY_PLUGIN_OPTIONS="-D zeek -d"``,
    you'll actually get the complete output of both what the compiler
    is doing (per above) and what's happening at runtime. That may be
    more convenient, but `HILTI_DEBUG` can do more (see below) and
    might be the better starting point.

So we know now that our analyzer is receiving the anticipated data to
parse. At this point, we can switch to debugging the Spicy side
:ref:`through the usual mechanisms <debugging>`. In particular,
setting ``HILTI_DEBUG=spicy`` tends to be helpful::

    # HILTI_DEBUG=spicy SPICY_PLUGIN_OPTIONS="-d" zeek -Cr request-line.pcap my-http.spicy my-http.evt
    [spicy] MyHTTP::RequestLine
    [spicy]   method = GET
    [spicy]   anon_2 =
    [spicy]   uri = /index.html
    [spicy]   anon_3 =
    [spicy]   MyHTTP::Version
    [spicy]     anon = HTTP/
    [spicy]     number = 1.0
    [spicy]   version = [$number=b"1.0"]
    [spicy]   anon_4 = \n

If everything looks right with the parsing, and the right events are
generated too, then the final part is to check out the events that
arrive on the Zeek side. To get Zeek to see an event that the plugin
raises, you need to have at least one handler implemented for it in
one of your Zeek scripts. You can then load Zeek's
``misc/dump-events`` to see them as they are being received, including
their full Zeek-side values::

    # zeek -Cr request-line.pcap my-http.spicy my-http.evt misc/dump-events
    [...]
    1580991211.780489 MyHTTP::request_line
                  [0] c: connection      = [id=[orig_h=127.0.0.1, orig_p=59619/tcp, ...] ...]
                  [1] method: string     = GET
                  [2] uri: string        = /index.html
                  [3] version: string    = 1.0
    [...]
