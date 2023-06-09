
.. _zeek_plugin:

================
Zeek Integration
================

While Spicy itself remains application independent, transparent
integration into `Zeek <https://zeek.org>`_ has been a primary goal
for its development from early on. While historically an external Zeek
plugin was required to use Spicy parsers with Zeek, Zeek has now been
shipping with built-in Spicy support since version 5.0. That means you
can directly add new protocol, file, and packet analyzers to Zeek
through Spicy without needing to write any further code. In the
following, we dig deeper into how to use all of this.

.. note::

    There are a number of pieces involved in creating a full Zeek
    analyzer, in particular if you want to distribute it as a Zeek
    package. To help you get started with that, Zeek's package manager
    can create a skeleton Spicy package by running::

        # zkg create --features=spicy-protocol-analyzer --packagedir <packagedir>

    The generated files mark places that will need manual editing with
    ``TODO``. See the :ref:`tutorial <zkg_create_package>` for more on
    this.

.. _zeek_terminology:

Terminology
===========

In Zeek, the term "analyzer" generally refers to a component that
processes a particular protocol ("protocol analyzer"), file format
("file analyzer"), or low-level packet structure ("packet analyzer").
"Processing" here means more than just parsing content: An analyzer
controls when it wants to be used (e.g., with connections on specific
ports, or with files of a specific MIME type); what events to generate
for Zeek's scripting layer; and how to handle any errors occurring
during parsing. While Spicy itself focuses just on the parsing part,
Spicy makes it possible to provide the remaining pieces to
Zeek, turning a Spicy parser into a full Zeek analyzer. That's what we
refer to as a "Spicy (protocol/file/packet) analyzer" for Zeek.

.. _zeek_installation:

Installation
============

Since Zeek version 5.0, support for Spicy is by default bundled with
Zeek. To confirm that Spicy is indeed available, you can inspect the
output of ``zeek -N``::

    # zeek -N Zeek::Spicy
    Zeek::Spicy - Support for Spicy parsers (*.hlto) (built-in)

It remains possible to build Zeek against an external Spicy
installation through Zeek's ``configure`` option
``--with-spicy=PATH``, where ``PATH`` points to the Spicy installation
directory. In that case, you also need to ensure that the Spicy tools
(e.g., ``spicyc``, ``spicy-config``) are available in ``PATH``.

Interface Definitions ("evt files")
===================================

Per above, a Spicy analyzer for Zeek does more than just parsing data.
Accordingly, we need to tell Zeek a couple of additional
pieces about analyzers we want it to provide to Zeek:

Analyzer setup
    Zeek needs to know what type of analyzers we are creating,
    when we want Zeek to activate them, and what Spicy unit types to
    use as their parsing entry point.

Event definitions
   We need to tell Zeek which events to provide and
   when to trigger them.

We define all of these through custom interface definition files that
Spicy's compiler for Zeek reads in. These files use an ``*.evt``
extension, and the following subsections discuss their content in more
detail.

Generally, empty lines and comments starting with ``#`` are ignored in
an ``*.evt``.

.. note::

    The syntax for ``*.evt`` files comes with some legacy pieces that
    aren't particularly pretty. We may clean that up at some point.

.. _zeek_evt_analyzer_setup:

Analyzer Setup
--------------

You can define protocol analyzers, packet analyzers and file analyzers in an
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
        for port constants <type_port>` (e.g., ``80/tcp``), or as a port range
        ``PORT_START-PORT_END`` where start and end port are port constants
        forming a closed interval. The ports' transport protocol must match
        that of the analyzer.

        .. note::

            Zeek will also honor any ``%port`` :ref:`meta data
            property <unit_meta_data>` that the responder-side
            ``SPICY_UNIT`` may define (as long as the attribute's
            direction is not ``originator``).

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

As a full example, here's what a new HTTP analyzer could look like:

.. code-block:: spicy-evt

    protocol analyzer spicy::HTTP over TCP:
        parse originator with HTTP::Requests,
        parse responder with HTTP::Replies,
        port 80/tcp,
        replaces HTTP;


.. _zeek_packet_analyzer:
.. rubric:: Packet Analyzer

Defining packet analyzers works quite similar to protocol analyzers through
``*.evt`` sections like this::

    packet analyzer ANALYZER_NAME:
        PROPERTY_1,
        PROPERTY_2,
        ...
        PROPERTY_N;

Here, ``ANALYZER_NAME`` is again a name to identify your analyzer
inside Zeek.  On the Zeek-side, the name will be added to Zeek's
``PacketAnalyzer::Tag`` enum.

Packet analyzers support the following properties:

    ``parse with SPICY_UNIT``
        Specifies the top-level Spicy unit the analyzer uses for
        parsing each packet, with ``SPICY_UNIT`` being a fully-qualified
        Spicy-side type name. The unit type must have been declared as
        ``public`` in Spicy.

    ``replaces ANALYZER_NAME``
        Disables an existing packet analyzer that Zeek already
        provides internally, allowing you to replace a built-in
        analyzer with a new Spicy version. ``ANALYZER_NAME`` is the
        Zeek-side name of the existing analyzer. To find that name,
        inspect the output of ``zeek -NN`` for available analyzers::

            # zeek -NN | grep '\[Packet Analyzer\]'
            ...
            [Packet Analyzer] Ethernet (ANALYZER_ETHERNET)
            ...

        Here, ``Ethernet`` is the name you would give to ``replaces``
        to disable the built-in Ethernet analyzer.

        When replacing an existing packet analyzer, you still need to
        configure your new analyzer on the Zeek side through a
        `zeek_init()` event handler. See below for more.

        .. note::

            This feature requires Zeek >= 5.2.

As a full example, here's what a new packet analyzer could look like::

    packet analyzer spicy::RawLayer:
        parse with RawLayer::Packet;

In addition to the Spicy-side configuration, packet analyzers also
need to be registered with Zeek inside a ``zeek_init`` event handler;
see the `Zeek documentation
<https://docs.zeek.org/en/master/frameworks/packet-analysis.html>`_
for more. The ``-NN`` output shows your new analyzer's ``ANALYZER_*``
tag to use.

.. note::

    Depending on relative loading order between your analyzer and
    Zeek's scripts, in some situations you may not have access to the
    ``ANALYZER_*`` tag referring to your new analyzer. If you run into
    this, use `PacketAnalyzer::try_register_packet_analyzer_by_name
    <https://docs.zeek.org/en/master/scripts/base/bif/packet_analysis.bif.zeek.html#id-PacketAnalyzer::try_register_packet_analyzer_by_name>`_
    to register your Spicy analyzer by name (as shown by ``-NN``).
    Example:

    .. code-block:: zeek

        event zeek_init()
            {
            if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x88b5, "spicy::RawLayer") )
                    Reporter::error("unknown analyzer name used");
            }


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
        the network. The type is specified in standard
        ``type/subtype`` notion, without quotes (e.g., ``image/gif``).

        .. note::

            Zeek will also honor any ``%mime-type`` :ref:`meta
            data property <unit_meta_data>` that the ``SPICY_UNIT``
            may define.

        .. note::

            Keep in mind that Zeek identifies MIME types through
            "content sniffing" (i.e., similar to libmagic), and
            usually not by protocol-level headers (e.g., *not* through
            HTTP's ``Content-Type`` header). If in doubt, examine
            ``files.log`` for what it records as a file's type.

    ``replaces ANALYZER_NAME``
        Disables an existing file analyzer that Zeek already provides
        internally, allowing you to replace a built-in analyzer with a new
        Spicy version. ``ANALYZER_NAME`` is the Zeek-side name of the
        analyzer. To find that name, inspect the output of ``zeek -NN``
        for available analyzers::

            # zeek -NN | grep '\[File Analyzer\]'
            ...
            [File Analyzer] PE (ANALYZER_PE, enabled)
            ...

        Here, ``PE`` is the name you would write into ``replaces`` to
        disable the built-in PE analyzer.

        .. note::

            This feature requires Zeek >= 4.1.

As a full example, here's what a new GIF analyzer could look like:

.. code-block:: spicy-evt

    file analyzer spicy::GIF:
        parse with GIF::Image,
        mime-type image/gif;

.. _zeek_events:

Event Definitions
-----------------

To define a Zeek event that you want the Spicy analyzer to trigger, you
add lines of the form::

    on HOOK_ID -> event EVENT_NAME(ARG_1, ..., ARG_N);

    on HOOK_ID if COND -> event EVENT_NAME(ARG_1, ..., ARG_N);

Zeek automatically derives from this everything it needs to
register new events with Zeek, including a mapping of the arguments'
Spicy types to corresponding Zeek types. More specifically, these are
the pieces going into such an event definition:

``on HOOK_ID``
    A Spicy-side ID that defines when you want to trigger the event.
    This works just like an ``on ...`` :ref:`unit hook <unit_hooks>`,
    and you can indeed use anything here that Spicy supports for those
    as well (except :ref:`container hooks <foreach>`). So, e.g., ``on
    HTTP::Request::%done`` triggers an event whenever a
    ``HTTP::Request`` unit has been fully parsed, and ``on
    HTTP::Request::uri`` leads to an event each time the ``uri`` field
    has been parsed. (In the former example you may skip the
    ``%done``, actually: ``on HTTP::Request`` implicitly adds it.)

``EVENT_NAME``
    The Zeek-side name of the event you want to generate, preferably
    including a namespace (e.g., ``http::request``).

``ARG_1, ..., ARG_N``
    Arguments to pass to the event, given as arbitrary Spicy
    expressions. Each expression will be evaluated within the context of
    the unit that the ``on ...`` triggers on, similar to code running
    inside the body of a corresponding :ref:`unit hook <unit_hooks>`.
    That means the expression has access to ``self`` for accessing
    the unit instance that's currently being parsed.

    The Spicy type of the expression determines the Zeek-side type of
    the corresponding event argument. Most Spicy types translate
    over pretty naturally, the following summarizes the translation:

    .. _zeek-event-arg-types:

    .. csv-table:: Type Conversion from Spicy to Zeek
        :header: "Spicy Type", "Zeek Type", "Notes"

        ``addr``, ``addr``,
        ``bool``, ``bool``,
        ``enum { ... }``, ``enum { ... }``, [1]
        ``int(8|16|32|64)``, ``int``,
        ``interval``, ``interval``,
        ``list<T>``, ``vector of T``,
        "``map<V,K>``", "``table[V] of K``",
        ``optional<T>``, ``T``,  [2]
        ``port``, ``port``,
        ``real``, ``double``,
        ``set<T>``, ``set[T]``,
        ``string``, ``string``,
        ``time``, ``time``,
        "``tuple<T_1, ... ,T_N>``", "``record { T1, ..., T_N }``", [3]
        ``uint(8|16|32|64)``, ``count``,
        ``vector<T>``, ``vector of T``,

    .. note::

        [1]
            A corresponding Zeek-side ``enum`` type is automatically
            created. See :ref:`below <zeek_enum>` for more.

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
            Zeek type ``fa_file``. This ID can be used with file or protocol
            analyzers. For protocol analyzers it refers to the most recently
            opened, but not yet closed file, see :ref:`zeek::file_begin
            <spicy_file_begin>` and :ref:`zeek::file_end <spicy_file_end>`.

        ``$packet``
            Refers to the packet that's currently being processed by
            Zeek. On the Zeek-side this will turn into a parameter of
            Zeek type ``raw_pkt_hdr``, with any fields filled in that
            have already been parsed by Zeek's built-in analyzers.
            This ID can be used only with packet analyzers. (Note that
            instantiation of ``raw_pkt_hdr`` values can be relatively
            expensive on the Zeek side, so best to limit usage of this
            ID to a small part of the overall traffic.)

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


.. _zeek_export_types:

Exporting Types
---------------

As we :ref:`discuss above <zeek_events>`, the type of each event
argument maps over to a corresponding Zeek type. On the Zeek side,
that corresponding type needs to be known by Zeek. That is always the
case for built-in atomic types (per :ref:`the conversion table
<zeek-event-arg-types>`), but it can turn out more challenging
to achieve for custom types, such as ``enum`` and ``record``, for
which you would normally need to create matching type declarations in
your Zeek scripts. While that's not necessarily hard, but it can
become quite cumbersome.

Fortunately, there's help: for most types, Zeek can
instantiate corresponding types automatically as it loads the
corresponding analyzer. While you will never actually see the
Zeek-side type declarations, they will be available inside your Zeek
scripts as if you had typed them out yourself--similar to other types
that are built into Zeek itself.

To have the Zeek create a type for your analyzer automatically,
you need to ``export`` the Spicy type in your EVT file. The syntax for
that is::

    export SPICY_ID [as ZEEK_ID];

Here, ``SPICY_ID`` is the fully-scoped type ID on the Spicy side, and
``ZEEK_ID`` is the fully-scoped type ID you want in Zeek. If you leave
out the ``as ...`` part, the Zeek name will be the same as the Spicy
name, including its namespace. For example, say you have a Spicy unit
``TFTP::Request``. Adding ``export TFTP::Request;`` to your EVT file
will make a ``record`` type of the same name, and with the same
fields, available in Zeek. If you instead use ``export TFTP::Request
as TheOtherTFTP::Request``, it will be placed into a different
namespace instead.

Exporting types generally works for most Spicy types as long as
there's an ID associated with them in your Spicy code. However,
exporting is most helpful with user-defined types, such as ``enum``
and ``unit``, because it can save you quite a bit of typing there. We
discuss the more common type conversions in more detail below.

To confirm the types made available to Zeek, you can see all exports
in the output of ``zeek -NN``. With our 2nd ``TFTP::Request``
example, that looks like this::

    [...]
    # zeek -NN Zeek::Spicy
    Zeek::Spicy - Support for Spicy parsers (*.hlto)
        [Type] TheOtherTFTP::Request
    [...]

.. note::

   Most, but not all, types can be exported automatically.  For
   example, self-recursive types are currently not supported.
   Generally, if you run into trouble exporting a type, you can always
   fall back to declaring a corresponding Zeek version yourself in
   your Zeek script. Consider the ``export`` mechanism as a
   convenience feature that helps avoid writing a lot of boiler plate
   code in common cases.

.. _zeek_enum:

Enum Types
^^^^^^^^^^

When you export a Spicy ``enum`` type, Zeek creates a
corresponding Zeek ``enum`` type. For example, assume the following
Spicy declaration:

.. spicy-code::

    module Test;

    type MyEnum = enum {
        A = 83,
        B = 84,
        C = 85
    };

Using ``export Test::MyEnum;``, Zeek will create the equivalent
of the following Zeek type for use in your scripts:

.. code-block:: zeek

    module Test;

    export {

      type MyEnum: enum {
          MyEnum_A = 83,
          MyEnum_B = 84,
          MyEnum_A = 85,
          MyEnum_Undef = -1
      };

    }

(The odd naming is due to ID limitations on the Zeek side.)

.. note::

    For backward compatibility, the ``enum`` type comes with an
    additional property: all *public* enum types are automatically
    exported, even without adding any ``export`` to your EVT file.
    This feature may go away at some point, and we suggest to not rely
    on it on new code; always use ``export`` for `enum` types as well.

.. _zeek_unit:

Unit Types
^^^^^^^^^^

When you export a Spicy ``unit`` type, Zeek creates a
corresponding Zeek ``record`` type. For example, assume the following
Spicy declaration:

.. spicy-code::

    module Test;

    type MyRecord = unit {
        a: bytes &size=4;
        b: uint16;

        var c: bool;
    };

Using ``export Test::MyRecord;``, Zeek will then create the
equivalent of the following Zeek type for use in your scripts:

.. code-block:: zeek

    module Test;

    export {

      type MyRecord: record {
        a: string &optional;
        b: count &optional;
        c: bool;
      };

    }

The individual fields map over just like event arguments do, following
the :ref:`the table <zeek-event-arg-types>` above. For aggregate
types, this works recursively: if, e.g., a field is itself of unit
type *and that type has been exported as well*, Zeek will map it
over accordingly to the corresponding ``record`` type. Note that such
dependent types must be exported *first* in the EVT file for this to
work. As a result, you cannot export self-recursive unit types.

As you can see in the example, unit fields are always declared as
optional on the Zeek-side, as they may not have been set during
parsing. Unit variables are non-optional by default, unless declared
as ``&optional`` in Spicy.

.. _zeek_struct:

Struct Types
^^^^^^^^^^^^

A Spicy ``struct`` type maps over to Zeek in the same way as ``unit``
types do, treating each field like a unit variable. See :ref:`there
<zeek_unit>` for more information.

Tuple Types
^^^^^^^^^^^

A Spicy ``tuple`` type maps over to a Zeek ``record`` similar to how
``unit`` types do, treating each tuple element like a unit variable.
See :ref:`there <zeek_unit>` for more information.

Exporting works only for ``tuple`` types that declare names for all
their elements.

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

.. _zeek_conditional_compilation:

Conditional Compilation
-----------------------

``*.evt`` files offer the same basic form of :ref:`conditional
compilation <conditional_compilation>` through
``@if``/``@else``/``@endif`` blocks as Spicy scripts. Zeek
makes two additional identifiers available for testing to both
``*.evt`` and ``*.spicy`` code:

    ``HAVE_ZEEK``
        Always set to 1 by Zeek. This can be used for feature
        testing from Spicy code to check if it's being compiled for
        Zeek.

    ``ZEEK_VERSION``
        The numerical Zeek version that's being compiled for (see
        ``zeek -e 'print Version::number'``).

This is an example bracketing code by Zeek version in an EVT file:

.. code-block:: spicy-evt

    @if ZEEK_VERSION < 30200
        <EVT code for Zeek versions older than 3.2>
    @else
        <EVT code for Zeek version 3.2 or newer>
    @endif

.. _zeek_compiling:
.. _spicyz:

Compiling Analyzers
====================

Once you have the ``*.spicy`` and ``*.evt`` source files for your new
analyzer, you need to precompile them into an ``*.hlto`` object file
containing their final executable code, which Zeek will then use. To
do that, pass the relevant ``*.spicy`` and ``*.evt`` files to
``spicyz``, then have Zeek load the output. To repeat the
:ref:`example <example_zeek_my_http>` from the *Getting Started*
guide::

    # spicyz -o my-http-analyzer.hlto my-http.spicy my-http.evt
    # zeek -Cr request-line.pcap my-http-analyzer.hlto my-http.zeek
    Zeek saw from 127.0.0.1: GET /index.html 1.0

Instead of providing the precompiled analyzer on the Zeek command
line, you can also copy them into
``${prefix}/lib/spicy/Zeek_Spicy/modules``. Zeek will
automatically load any ``*.hlto`` object files it finds there. In
addition, Zeek also scans its plugin directory for ``*.hlto``
files. Alternatively, you can override both of those locations by
setting the environment variable ``ZEEK_SPICY_MODULE_PATH`` to a set of
colon-separated directories to search instead. Zeek will then
*only* look there. In all cases, Zeek searches any directories
recursively, so it will find ``*.hlto`` also if they are nested in
subfolders.

Run ``spicyz -h`` to see some additional options it provides, which
are similar to :ref:`spicy-driver`.

.. _zeek_functions:

Controlling Zeek from Spicy
===========================

Spicy grammars can import a provided library module ``zeek`` to gain
access to Zeek-specific functions that call back into Zeek's
processing:

.. include:: /autogen/zeek/zeek-functions.spicy

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

2. You should call :ref:`spicy::accept_input() <spicy_accept_input>`
   from a hook inside your grammar at a point when the parser can be
   reasonably certain that it is processing the expected protocol.
   Optionally, you may also call :ref:`spicy::decline_input()
   <spicy_decline_input>` when you're sure the parser is *not* parsing
   the right protocol. However, Zeek will also trigger this
   automatically whenever your parser aborts with an error.

.. _zeek_configuration:

Configuration
=============

Options
-------

Zeek provides a set of script-level options to tune Spicy
behavior. These all live in the ``Spicy::`` namespace:

.. literalinclude:: /autogen/zeek/init-bare.zeek
    :language: zeek
    :start-after: doc-options-start
    :end-before:  doc-options-end

Functions
---------

Zeek also adds the following new built-in functions for Spicy, which
likewise live in the ``Spicy::`` namespace:

.. literalinclude:: /autogen/zeek/init-framework.zeek
    :language: zeek
    :start-after: doc-functions-start
    :end-before:  doc-functions-end

.. _zeek_debugging:

Debugging
=========

If Zeek doesn't seem to be doing the right thing with your Spicy
analyzer, there are several ways to debug what's going on. To
facilitate that, compile your analyzer with ``spicyz -d`` and, if
possible, use a debug version of Zeek (i.e., build Zeek with
``./configure --enable-debug``).

If your analyzer doesn't seem to be active at all, first make sure
Zeek actually knows about it: It should show up in the output of
``zeek -NN Zeek::Spicy``. If it doesn't, you might not have been using
the right ``*.spicy`` or ``*.evt`` files when precompiling, or Zeek is
not loading the ``*.hlto`` file. Also check your ``*.evt`` if it
defines your analyzer correctly.

If Zeek knows about your analyzer and just doesn't seem to activate
it, double-check that ports or MIME types are correct in the ``*.evt``
file. If you're using a signature instead, try a port/MIME type first,
just to make sure it's not a matter of signature mismatches.

If there's nothing obviously wrong with your source files, you can
trace what the Zeek's Spicy support is compiling by running ``spicyz``
with ``-D zeek``. For example, reusing the :ref:`HTTP example
<example_zeek_my_http>` from the *Getting Started* guide::

    # spicyz -D zeek my-http.spicy my-http.evt -o my-http.hlt
    [debug/zeek] Loading Spicy file "/Users/robin/work/spicy/main/tests/spicy/doc/my-http.spicy"
    [debug/zeek] Loading EVT file "/Users/robin/work/spicy/main/doc/examples/my-http.evt"
    [debug/zeek] Loading events from /Users/robin/work/spicy/main/doc/examples/my-http.evt
    [debug/zeek]   Got protocol analyzer definition for spicy_MyHTTP
    [debug/zeek]   Got event definition for MyHTTP::request_line
    [debug/zeek] Running Spicy driver
    [debug/zeek]   Got unit type 'MyHTTP::Version'
    [debug/zeek]   Got unit type 'MyHTTP::RequestLine'
    [debug/zeek] Adding protocol analyzer 'spicy_MyHTTP'
    [debug/zeek] Adding Spicy hook 'MyHTTP::RequestLine::0x25_done' for event MyHTTP::request_line
    [debug/zeek] Done with Spicy driver

You can see the main pieces in there: The files being loaded, unit
types provided by them, analyzers and events being created.

If that all looks as expected, it's time to turn to the Zeek side and
see what it's doing at runtime. You'll need a debug version of Zeek
for that, as well as a small trace with traffic that you expect your
analyzer to process. Run Zeek with ``-B dpd`` (or ``-B file_analysis``
if you're debugging a file analyzer) on your trace to record the
analyzer activity into ``debug.log``. For example, with the same HTTP
example, we get:

.. code-block:: text
    :linenos:

    # zeek -B dpd -Cr request-line.pcap my-http.hlto
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

To see this from the Zeek side, set the ``zeek`` debug stream
through the ``HILTI_DEBUG`` environment variable::

    # HILTI_DEBUG=zeek zeek -Cr request-line.pcap my-http.hlto
    [zeek] Have Spicy protocol analyzer spicy_MyHTTP
    [zeek] Registering Protocol::TCP protocol analyzer spicy_MyHTTP with Zeek
    [zeek]   Scheduling analyzer for port 12345/tcp
    [zeek] Done with post-script initialization
    [zeek] [SPICY_MYHTTP/7/orig] initial chunk: |GET /index.html HTTP/1.0\\x0a| (eod=false)
    [zeek] [SPICY_MYHTTP/7/orig] -> event MyHTTP::request_line($conn, GET, /index.html, 1.0)
    [zeek] [SPICY_MYHTTP/7/orig] done with parsing
    [zeek] [SPICY_MYHTTP/7/orig] parsing finished, skipping further originator payload
    [zeek] [SPICY_MYHTTP/7/resp] no unit specified for parsing
    [zeek] [SPICY_MYHTTP/7/orig] skipping end-of-data delivery
    [zeek] [SPICY_MYHTTP/7/resp] no unit specified for parsing
    [zeek] [SPICY_MYHTTP/7/orig] skipping end-of-data delivery
    [zeek] [SPICY_MYHTTP/7/resp] no unit specified for parsing

After the initial initialization, you see the data arriving and the
event being generated for Zeek. Zeek also reports that we didn't
define a unit for the responder side---which we know in this case, but
if that appears unexpectedly you probably found a problem.

So we know now that our analyzer is receiving the anticipated data to
parse. At this point, we can switch to debugging the Spicy side
:ref:`through the usual mechanisms <debugging>`. In particular,
setting ``HILTI_DEBUG=spicy`` tends to be helpful::

    # HILTI_DEBUG=spicy zeek -Cr request-line.pcap my-http.hlto
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
arrive on the Zeek side. To get Zeek to see an event that Zeek
raises, you need to have at least one handler implemented for it in
one of your Zeek scripts. You can then load Zeek's
``misc/dump-events`` to see them as they are being received, including
their full Zeek-side values::

    # zeek -Cr request-line.pcap my-http.hlto misc/dump-events
    [...]
    1580991211.780489 MyHTTP::request_line
                  [0] c: connection      = [id=[orig_h=127.0.0.1, orig_p=59619/tcp, ...] ...]
                  [1] method: string     = GET
                  [2] uri: string        = /index.html
                  [3] version: string    = 1.0
    [...]
