
.. _tutorial:

=========================
Tutorial: A Real Analyzer
=========================

In this chapter we will develop a simple protocol analyzer from
scratch, including full Zeek integration. Our analyzer will parse the
*Trivial File Transfer Protocol (TFTP)* in its original incarnation,
as described in `RFC 1350 <https://tools.ietf.org/html/rfc1350>`_.
TFTP provides a small protocol for copying files from a server to a
client system. It is most commonly used these days for providing boot
images to devices during initialization. The protocol is sufficiently
simple that we can walk through it end to end. See its `Wikipedia page
<https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol>`_ for
more background.

.. rubric:: Contents

.. contents::
    :local:

Creating a Spicy Grammar
========================

We start by developing Spicy grammar for TFTP. The protocol is
packet-based, and our grammar will parse the content of one TFTP
packet at a time. While TFTP is running on top of UDP, we will leave
the lower layers to Zeek and have Spicy parse just the actual UDP
application-layer payload, as described in `Section 5
<https://tools.ietf.org/html/rfc1350#section-5>`_ of the protocol
standard.

Parsing One Packet Type
-----------------------

TFTP is a binary protocol that uses a set of standardized, numerical
opcodes to distinguish between different types of packets---a common
idiom with such protocols. Each packet contains the opcode inside the
first two bytes of the UDP payload, followed by further fields that
then differ by type. For example, the following is the format of a
TFTP "Read Request" (RRQ) that initiates a download from a server::

            2 bytes     string    1 byte     string   1 byte    (from RFC 1350)
            ------------------------------------------------
           | Opcode |  Filename  |   0  |    Mode    |   0  |
            ------------------------------------------------

A Read Request uses an opcode of 1. The *filename* is a sequence of
ASCII bytes terminated by a null byte. The *mode* is another
null-terminated byte sequence that usually is either ``netascii``,
``octet``, or ``mail``, describing the desired encoding for data that
will be received.

Let's stay with the Read Request for a little bit and write a Spicy
parser just for this one packet type. The following is a minimal Spicy
unit to parse the three fields:

.. spicy-code:: rrq.spicy

    module TFTP;                          # [1]

    public type ReadRequest = unit {      # [2]
        opcode:   uint16;                 # [3]
        filename: bytes &until=b"\x00";   # [4]
        mode:     bytes &until=b"\x00";   # [5]

        on %done { print self; }          # [6]
    };

Let's walk through:

    - ``[1]`` All Spicy source files must start with a ``module`` line
      defining a namespace for their content. By convention, the
      namespace should match what is being parsed, so we call ours
      ``TFTP``. Naming our module ``TFTP`` also implies saving it
      under the name ``tftp.spicy``, so that other modules can find it
      through ``import TFTP;``. See :ref:`modules` for more on all of
      this.

    - ``[2]`` In Spicy, one will typically create a ``unit`` type for
      each of the main data units that a protocol defines. We want to
      parse a Read Request, so we call our type accordingly. We
      declare it as public because we want to use this unit as the
      starting point for parsing data. The following lines then lay
      out the elements of such a request in the same order as the
      protocol defines them.

    - ``[3]`` Per the TFTP specification, the first field contains the
      ``opcode`` as an integer value encoded over two bytes. For
      multi-byte integer values, it is important to consider the byte
      order for parsing. TFTP uses `network byte order
      <https://en.wikipedia.org/wiki/Endianness#Networking>`_ which
      matches Spicy's default, so there is nothing else for us to do
      here. (If we had to specify the order, we would add the
      :ref:`&byte-order <attribute_order>` attribute).

    - ``[4]`` The filename is a null-terminated byte sequence, which
      we can express directly as such in Spicy: The ``filename`` field
      will accumulate bytes until a null byte is encountered. Note
      that even though the specification of a Read Request shows the
      ``0`` as separate element inside the packet, we don't create a
      field for it, but rather exploit it as a terminator for the file
      name (which will not be included into the ``filename`` stored).

    - ``[5]`` The ``mode`` operates just the same as the
      ``filename``.

    - ``[6]`` Once we are done parsing a Read Request, we print out
      the result for debugging.

We should now be able to parse a Read Request. To try it, we need the
actual payload of a corresponding packet. With TFTP, the format is
simple enough that we can start by faking data with ``printf``
and pipe that into the Spicy tool :ref:`spicy-driver <spicy-driver>`:

.. spicy-output:: rrq.spicy 1
    :exec: printf '\000\001rfc1350.txt\000octet\000' | spicy-driver %INPUT
    :show-with: tftp.spicy

Here, ``spicy-driver`` compiles our ``ReadRequest`` unit into an
executable parser and then feeds it with the data it is receiving on
standard input. The output of ``spicy-driver`` is the result of our
``print`` statement executing at the end.

What would we do with a more complex protocol where we cannot easily use
``printf`` to create some dummy payload? We would probably have access
to some protocol traffic in pcap traces, however we can't just feed
those into ``spicy-driver`` directly as they will contain all the
other network layers as well that our grammar does not handle (e.g.,
IP and UDP). One way to test with a trace would be proceeding with
Zeek integration at this point, so that we could let Zeek strip off
the base layers and then feed our parser only the TFTP payload.
However, during development it is often easier at first to extract
application-layer protocol data from the traces ourselves, write it
into files, and then feed those files into ``spicy-driver``.

We can leverage Zeek for doing this extraction into files. If we had a
TCP-based protocol, doing so would be trivial because Zeek has that
functionality built in: When you run Zeek on a pcap trace and add
``Conn::default_extract=T`` to the command line, it will write out all
the TCP streams into individual files. As TFTP is UDP-based, however,
we will use a custom script, :download:`udp-contents.zeek
<examples/udp-contents.zeek>`. When you run Zeek with that script on
trace, you will get one file per UDP packet each containing the
corresponding application-layer UDP payload (make sure to use this
with small traces only ...).

Let's use the UDP script with :download:`tftp_rrq.pcap
<examples/tftp_rrq.pcap>`, a tiny TFTP trace containing a single file
download from `Wireshark's pcap archive
<https://wiki.wireshark.org/SampleCaptures#tftp>`_. ``tcpdump`` shows
us that the first packet indeed contains a Read Request:

.. code::

    # tcpdump -ttnr tftp_rrq.pcap
    1367411051.972852 IP 192.168.0.253.50618 > 192.168.0.10.69:  20 RRQ "rfc1350.txtoctet" [\|tftp]
    1367411052.077243 IP 192.168.0.10.3445 > 192.168.0.253.50618: UDP, length 516
    1367411052.081790 IP 192.168.0.253.50618 > 192.168.0.10.3445: UDP, length 4
    [...]

Running Zeek on the trace with the ``udp-contents`` scripts produces
the expected content files:

.. code::

    # zeek -r tftp_rrq.pcap udp-contents
    # ls udp-contents.orig.*
    udp-contents.orig.1367411051.972852.dat
    udp-contents.orig.1367411052.077243.dat
    udp-contents.orig.1367411052.086300.dat
    udp-contents.orig.1367411052.088995.dat
    udp-contents.orig.1367411052.091675.dat
    [...]

Per the timestamps included with the names, the first file is the one
containing our Read Request. We can pass that into our Spicy parser:

.. spicy-output:: rrq.spicy 2
    :exec: cat tutorial/examples/udp-contents.orig.1367411051.972852.dat | spicy-driver %INPUT
    :show-as: cat udp-contents.orig.1367411051.972852.dat | spicy-driver tftp.spicy

That gives us an easy way to test our TFTP parser.

Generalizing to More Packet Types
---------------------------------

So far we can parse a Read Request, but nothing else. In fact, we are
not even examining the ``opcode`` yet at all to see if our input
actually *is* a Read Request. To generalize our grammar to other TFTP
packet types, we will need to parse the ``opcode`` on its own first,
and then use the value to decide how to handle subsequent data. Let's
start over with a minimal version of our TFTP grammar that looks at
just the opcode:

.. spicy-code:: tftp-1.spicy

    module TFTP;

    public type Packet = unit {
        opcode: uint16;

        on %done { print self; }
    };

.. spicy-output:: tftp-1.spicy
    :exec: cat tutorial/examples/udp-contents.orig.1367411051.972852.dat | spicy-driver %INPUT
    :show-as: cat udp-contents.orig.1367411051.972852.dat | spicy-driver tftp.spicy

Next we create a separate type to parse the fields that are specific
to a Read Request:

.. spicy-code::

    type ReadRequest = unit {
        filename: bytes &until=b"\x00";
        mode:     bytes &until=b"\x00";
    };

We do not declare this type as public because we will use it only
internally inside our grammar; it is not a top-level entry point for
parsing (that's ``Packet`` now).

Now we need to tie the two units together. We can do that by adding
the ``ReadRequest`` as a field to the ``Packet``, which will let Spicy
parse it as a sub-unit:

.. spicy-code:: tftp-2.spicy

    module TFTP;

    public type Packet = unit {
        opcode: uint16;
        rrq:    ReadRequest;

        on %done { print self; }
    };

    # %hide-begin%
    type ReadRequest = unit {
        filename: bytes &until=b"\x00";
        mode:     bytes &until=b"\x00";
    };
    # %hide-end%

.. spicy-output:: tftp-2.spicy
    :exec: cat tutorial/examples/udp-contents.orig.1367411051.972852.dat | spicy-driver %INPUT
    :show-as: cat udp-contents.orig.1367411051.972852.dat | spicy-driver tftp.spicy

However, this does not help us much yet: it still resembles our
original version in that it continues to hardcode one specific packet
type. But the direction of using sub-units is promising, we only need
to instruct the parser to leverage the ``opcode`` to decide what
particular sub-unit to use. Spicy provides a ``switch`` construct for
such dispatching:

.. spicy-code:: tftp-3.spicy

    module TFTP;

    public type Packet = unit {
        opcode: uint16;

        switch ( self.opcode ) {
            1 -> rrq: ReadRequest;
        };

        on %done { print self; }
    };

    # %hide-begin%
    type ReadRequest = unit {
        filename: bytes &until=b"\x00";
        mode:     bytes &until=b"\x00";
    };
    # %hide-end%

.. spicy-output:: tftp-3.spicy 1
    :exec: cat tutorial/examples/udp-contents.orig.1367411051.972852.dat | spicy-driver %INPUT
    :show-as: cat udp-contents.orig.1367411051.972852.dat | spicy-driver tftp.spicy

The ``self`` keyword always refers to the unit instance currently
being parsed, and we use that to get to the opcode for switching on.
If it is ``1``, we descend down into a Read Request.

What happens if it is something other than ``1``? Let's try it with
the first server-side packet, which contains a TFTP acknowledgment
(opcode 4):

.. spicy-output:: tftp-3.spicy 2
    :exec: cat tutorial/examples/udp-contents.resp.1367411052.081790.dat | spicy-driver %INPUT
    :show-as: cat udp-contents.resp.1367411052.081790.dat | spicy-driver tftp.spicy
    :expect-failure:

Of course it is now easy to add another unit type for handling such
acknowledgments:

.. spicy-code:: tftp-4.spicy

    # %hide-begin%
    module TFTP;
    # %hide-end%

    public type Packet = unit {
        opcode: uint16;

        switch ( self.opcode ) {
            1 -> rrq: ReadRequest;
            4 -> ack: Acknowledgement;
        };

        on %done { print self; }
    };

    type Acknowledgement = unit {
        num: uint16; # block number being acknowledged
    };
    # %hide-begin%

    type ReadRequest = unit {
        filename: bytes &until=b"\x00";
        mode:     bytes &until=b"\x00";
    };
    # %hide-end%

.. spicy-output:: tftp-4.spicy
    :exec: cat tutorial/examples/udp-contents.resp.1367411052.081790.dat | spicy-driver %INPUT
    :show-as: cat udp-contents.resp.1367411052.081790.dat | spicy-driver tftp.spicy

As expected, the output shows that our TFTP parser now descended into
the ``ack`` sub-unit while leaving ``rrq`` unset.

TFTP defines three more opcodes for other packet types: ``2`` is a
Write Request, ``3`` is file data being sent, and ``5`` is an error.
We will add these to our grammar as well, so that we get the whole
protocol covered (please refer to the RFC for specifics of each packet
type):

.. spicy-code:: tftp-complete-1.spicy

    module TFTP;

    public type Packet = unit {
        opcode: uint16;

        switch ( self.opcode ) {
            1 -> rrq:   ReadRequest;
            2 -> wrq:   WriteRequest;
            3 -> data:  Data;
            4 -> ack:   Acknowledgement;
            5 -> error: Error;
        };

        on %done { print self; }
    };

    type ReadRequest = unit {
        filename: bytes &until=b"\x00";
        mode:     bytes &until=b"\x00";
    };

    type WriteRequest = unit {
        filename: bytes &until=b"\x00";
        mode:     bytes &until=b"\x00";
    };

    type Data = unit {
        num:  uint16;
        data: bytes &eod; # parse until end of data (i.e., packet) is reached
    };

    type Acknowledgement = unit {
        num: uint16;
    };

    type Error = unit {
        code: uint16;
        msg:  bytes &until=b"\x00";
    };


This grammar works well already, but we can improve it a bit more.

Using Enums
-----------

The use of integer values inside the ``switch`` construct is not
exactly pretty: they are hard to read and maintain. We can improve our
grammar by using an enumerator type with descriptive labels instead.
We first declare an ``enum`` type that provides one label for each
possible opcode:

.. spicy-code::

    type Opcode = enum { RRQ = 1, WRQ = 2, DATA = 3, ACK = 4, ERROR = 5 };

Now we can change the ``switch`` to look like this:

.. spicy-code:: tftp-enum.spicy

    # %hide-begin%
    module TFTP;

    type Opcode = enum { RRQ = 1, WRQ = 2, DATA = 3, ACK = 4, ERROR = 5 };

    public type Packet = unit {
        opcode: uint16 &convert=Opcode($$);
    # %hide-end%

        switch ( self.opcode ) {
            Opcode::RRQ   -> rrq:   ReadRequest;
            Opcode::WRQ   -> wrq:   WriteRequest;
            Opcode::DATA  -> data:  Data;
            Opcode::ACK   -> ack:   Acknowledgement;
            Opcode::ERROR -> error: Error;
            };

    # %hide-begin%
        on %done { print self; }
    };

    type ReadRequest = unit {
        filename: bytes &until=b"\x00";
        mode:     bytes &until=b"\x00";
    };

    type WriteRequest = unit {
        filename: bytes &until=b"\x00";
        mode:     bytes &until=b"\x00";
    };

    type Data = unit {
        num:  uint16;
        data: bytes &eod; # parse until end of data (i.e., packet) is reached
    };

    type Acknowledgement = unit {
        num: uint16;
    };

    type Error = unit {
        code: uint16;
        msg:  bytes &until=b"\x00";
    };
    # %hide-end%

Much better, but there is a catch still: this will not compile because
of a type mismatch. The switch cases' expressions have type
``Opcode``, but ``self.opcode`` remains of type ``uint16``. That is
because Spicy cannot know on its own that the integers we parse into
``opcode`` match the numerical values of the ``Opcode`` labels. But
we can convert the former into the latter explicitly by adding a
:ref:`&convert <attribute_convert>` attribute to the ``opcode`` field:

.. spicy-code::

    public type Packet = unit {
        opcode: uint16 &convert=Opcode($$);
        ...
    };

This does two things:

1. Each time an ``uint16`` gets parsed for this field, it is not
   directly stored in ``opcode``, but instead first passed through the
   expression that ``&convert`` specifies. Spicy then stores the
   *result* of that expression, potentially adapting the field's type
   accordingly. Inside the ``&convert`` expression, the parsed value is
   accessible through the special identifier ``$$``.

2. Our ``&convert`` expression passes the parsed integer into the
   constructor for the ``Opcode`` enumerator type, which lets Spicy
   create an ``Opcode`` value with the label that corresponds to the
   integer value.

With this transformation, the ``opcode`` field now has type ``Opcode``
and hence can be used with our updated switch statement. You can see
the new type for ``opcode`` in the output as well:

.. spicy-output:: tftp-enum.spicy
    :exec: cat tutorial/examples/udp-contents.orig.1367411051.972852.dat | spicy-driver %INPUT
    :show-as: cat udp-contents.orig.1367411051.972852.dat | spicy-driver tftp.spicy

See :ref:`attribute_convert` for more on ``&convert``, and
:ref:`type_enum` for more on the ``enum`` type.

.. note::

    What happens when ``Opcode($$)`` receives an integer that does not
    correspond to any of the labels? Spicy permits that and will
    substitute an implicitly defined ``Opcode::Undef`` label. It will
    also retain the actual integer value, which can be recovered by
    converting the enum value back to an integer.

Using Unit Parameters
---------------------

Looking at the two types ``ReadRequest`` and ``WriteRequest``, we see
that both are using exactly the same fields. That means we do not
really need two separate types here, and could instead define a
single ``Request`` unit to cover both cases. Doing so is
straight-forward, except for one issue: when parsing such a
``Request``, we would now lose the information whether we are seeing
read or a write operation. For our Zeek integration later it will be
useful to retain that distinction, so let us leverage a Spicy
capability that allows passing state into a sub-unit: :ref:`unit
parameters <unit_parameters>`. Here's the corresponding excerpt after
that refactoring:

.. spicy-code:: tftp-unified-request.spicy

    # %hide-begin%
    module TFTP;

    type Opcode = enum { RRQ = 1, WRQ = 2, DATA = 3, ACK = 4, ERROR = 5 };
    # %hide-end%

    public type Packet = unit {
        opcode: uint16 &convert=Opcode($$);

        switch ( self.opcode ) {
            Opcode::RRQ   -> rrq:   Request(True);
            Opcode::WRQ   -> wrq:   Request(False);
            # ...
            # %hide-begin%
            Opcode::DATA  -> data:  Data;
            Opcode::ACK   -> ack:   Acknowledgement;
            Opcode::ERROR -> error: Error;
            # %hide-end%
            };

        on %done { print self; }
    };

    type Request = unit(is_read: bool) {
        filename: bytes &until=b"\x00";
        mode:     bytes &until=b"\x00";

        on %done { print "We got a %s request." % (is_read ? "read" : "write"); }
    };

    # %hide-begin%
    type Data = unit {
        num:  uint16;
        data: bytes &eod; # parse until end of data (i.e., packet) is reached
    };

    type Acknowledgement = unit {
        num: uint16; # block number being acknowledged
    };

    type Error = unit {
        code: uint16;
        msg:  bytes &until=b"\x00";
    };
    # %hide-end%

We see that the ``switch`` now passes either ``True`` or ``False``
into the ``Request`` type, depending on whether it is a Read Request
or Write Request. For demonstration, we added another ``print``
statement, so that we can see how that boolean becomes available
through the ``is_read`` unit parameter:

.. spicy-output:: tftp-unified-request.spicy
    :exec: cat tutorial/examples/udp-contents.orig.1367411051.972852.dat | spicy-driver %INPUT
    :show-as: cat udp-contents.orig.1367411051.972852.dat | spicy-driver tftp.spicy

Admittedly, the unit parameter is almost overkill in this
example, but it proves very useful in more complex grammars where one
needs access to state information, in particular also from
higher-level units. For example, if the ``Packet`` type stored
additional state that sub-units needed access to, they could receive
the ``Packet`` itself as a parameter.

Complete Grammar
----------------

Combining everything discussed so far, this leaves us with the
following complete grammar for TFTP, including the packet formats in
comments as well:

.. literalinclude:: /autogen/zeek/tftp-no-accept.spicy
    :language: spicy

Zeek Integration
================

To turn the Spicy-side grammar into a Zeek analyzer, we need to
provide Zeek with a description of how to employ it.
There are two parts to that: Telling Zeek when to activate the
analyzer, and defining events to generate. In addition, we will need a
Zeek-side script to do something with our new TFTP events. We will
walk through this in the following, starting with the mechanics of
compiling the Spicy analyzer for Zeek. While we will build up the
files involved individually first, see the :ref:`final section
<zkg_create_package>` for how the Zeek package manager, *zkg*, can be
used to bootstrap a new Zeek package with a skeleton of everything
needed for an analyzer.

Before proceeding, make sure that your Zeek comes with Spicy support
built-in---which is the default since Zeek version 5.0::

    # zeek -N Zeek::Spicy
    Zeek::Spicy - Support for Spicy parsers (*.hlto) (built-in)

You should also have ``spicyz`` in your ``PATH``::

    # which spicyz
    /usr/local/zeek/bin/spicyz

Compiling the Analyzer
----------------------

Zeek comes with a tool :ref:`spicyz <spicyz>` that compiles Spicy
analyzers into binary code that Zeek can load through a Spicy plugin.
The following command line produces a binary object file ``tftp.hlto``
containing the executable analyzer code:

.. code::

    # spicyz -o tftp.hlto tftp.spicy

Below, we will prepare an additional interface definition file
``tftp.evt`` that describes the analyzer's integration into Zeek. We
will need to give that to ``spicyz`` as well, and our full
compilation command hence becomes:

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt

When starting Zeek, we add ``tftp.hlto`` to its command line:

.. code::

    # zeek -r tftp_rrq.pcap tftp.hlto


Activating the Analyzer
-----------------------

In *Getting Started*, :ref:`we already saw
<example_zeek_my_http_adding_analyzer>` how to inform Zeek about a new
protocol analyzer. We follow the same scheme here and put the
following into ``tftp.evt``, the analyzer definition file:

.. literalinclude:: examples/tftp.evt
    :lines: 3-5
    :language: spicy-evt

The first line provides our analyzer with a Zeek-side name
(``spicy::TFTP``) and also tells Zeek that we are adding an
application analyzer on top of UDP (``over UDP``). ``TFTP::Packet``
provides the top-level entry point for parsing both sides of a TFTP
connection. Furthermore, we want Zeek to automatically activate our
analyzer for all sessions on UDP port 69 (i.e., TFTP's well known
port). See :ref:`zeek_evt_analyzer_setup` for more details on defining
such a ``protocol analyzer`` section.

With this in place, we can already employ the analyzer inside Zeek. It
will not generate any events yet, but we can at least see the output of
the ``on %done { print self; }`` hook that still remains part of the
grammar from earlier:

.. code::

    # zeek -r tftp_rrq.pcap tftp.hlto Spicy::enable_print=T
    [$opcode=Opcode::RRQ, $rrq=[$filename=b"rfc1350.txt", $mode=b"octet"], $wrq=(not set), $data=(not set), $ack=(not set), $error=(not set)]

As by default, the Zeek plugin does not show the output of Spicy-side
``print`` statements, we added ``Spicy::enable_print=T`` to the
command line to turn that on. We see that Zeek took care of the
lower network layers, extracted the UDP payload from the Read Request,
and passed that into our Spicy parser. (If you want to view more about
the internals of what is happening here, there are a couple kinds of
:ref:`debug output available <zeek_debugging>`.)

You might be wondering why there is only one line of output, even
though there are multiple TFTP packets in our pcap trace. Shouldn't
the ``print`` execute multiple times? Yes, it should, but it does not
currently: Due to some intricacies of the TFTP protocol, our analyzer
gets to see only the first packet for now. We will fix this later. For
now, we focus on the Read Request packet that the output above shows.

Defining Events
---------------

The core task of any Zeek analyzer is to generate events for Zeek
scripts to process. For binary protocols, events will often correspond
pretty directly to data units specified by their specifications---and
TFTP is no exception. We start with an event for Read/Write Requests
by adding this definition to ``tftp.evt``:

.. literalinclude:: examples/tftp-single-request.evt
    :lines: 5-7
    :language: spicy-evt

The first line makes our Spicy TFTP grammar available to the rest of
the file. The line ``on ...`` defines one event: Every time a
``Request`` unit will be parsed, we want to receive an event
``tftp::request`` with one parameter: the connection it belongs to.
Here, ``$conn`` is a reserved identifier that will turn into the
standard `connection record
<https://docs.zeek.org/en/current/scripts/base/init-bare.zeek.html#type-connection>`_
record on the Zeek side.

Now we need a Zeek event handler for our new event. Let's put this
into ``tftp.zeek``:

.. literalinclude:: examples/tftp-single-request.zeek
    :language: zeek

Running Zeek then gives us:

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt
    # zeek -r tftp_rrq.pcap tftp.hlto tftp.zeek
    TFTP request, [orig_h=192.168.0.253, orig_p=50618/udp, resp_h=192.168.0.10, resp_p=69/udp]

Let's extend the event signature a bit by passing further arguments:

.. literalinclude:: examples/tftp-single-request-more-args.evt
    :lines: 5-7
    :language: spicy-evt

This shows how each parameter gets specified as a Spicy expression:
``self`` refers to the instance currently being parsed (``self``), and
``self.filename`` retrieves the value of its ``filename`` field.
``$is_orig`` is another reserved ID that turns into a boolean that
will be true if the event has been triggered by originator-side
traffic. On the Zeek side, our event now has the following signature:

.. literalinclude:: examples/tftp-single-request-more-args.zeek
    :language: zeek

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt
    # zeek -r tftp_rrq.pcap tftp.hlto tftp.zeek
    TFTP request, [orig_h=192.168.0.253, orig_p=50618/udp, resp_h=192.168.0.10, resp_p=69/udp], T, rfc1350.txt, octet

Going back to our earlier discussion of Read vs Write Requests, we do
not yet make that distinction with the ``request`` event that we are
sending to Zeek-land. However, since we had introduced the ``is_read``
unit parameter, we can easily separate the two by gating event
generation through an additional ``if`` condition:

.. literalinclude:: examples/tftp.evt
    :lines: 9-10
    :language: spicy-evt

This now defines two separate events, each being generated only for
the corresponding value of ``is_read``. Let's try it with a new
``tftp.zeek``:

.. literalinclude:: examples/tftp-two-requests.zeek
    :language: zeek

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt
    # zeek -r tftp_rrq.pcap tftp.hlto tftp.zeek
    TFTP read request, [orig_h=192.168.0.253, orig_p=50618/udp, resp_h=192.168.0.10, resp_p=69/udp], T, rfc1350.txt, octet

If we look at the ``conn.log`` that Zeek produces during this run, we
will see that the ``service`` field is not filled in yet. That's
because our analyzer does not yet confirm to Zeek that it has been
successful in parsing the content. To do that, we can call a library
function that Spicy makes available once we have successfully parsed a
request: :ref:`spicy::accept_input <spicy_accept_input>`. That
function signals the host application---i.e., Zeek in our case—--that
the parser is processing the expected protocol. With that, our request
looks like this now:

.. spicy-code:: tftp-request-with-accept.spicy

    type Request = unit(is_read: bool) {
        filename: bytes &until=b"\x00";
        mode:     bytes &until=b"\x00";

        on %done { spicy::accept_input(); }
    };


Let's try it again:

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt
    # zeek -r tftp_rrq.pcap tftp.hlto tftp.zeek
    TFTP read request, [orig_h=192.168.0.253, orig_p=50618/udp, resp_h=192.168.0.10, resp_p=69/udp], T, rfc1350.txt, octet
    # cat conn.log
    [...]
    1367411051.972852  C1f7uj4uuv6zu2aKti  192.168.0.253  50618  192.168.0.10  69  udp  spicy_tftp  -  -  -  S0  -  -0  D  1  48  0  0  -
    [...]

Now the service field says TFTP! (There will be a 2nd connection in
the log that we are not showing here; see the next section on that).

Turning to the other TFTP packet types, it is straight-forward to add
events for them as well. The following is our complete ``tftp.evt``
file:

.. literalinclude:: examples/tftp.evt
    :lines: 3-
    :language: spicy-evt


Detour: Zeek vs. TFTP
---------------------

We noticed above that Zeek seems to be seeing only a single TFTP
packet from our input trace, even though ``tcpdump`` shows that the
pcap file contains multiple different types of packets. The reason
becomes clear once we look more closely at the UDP ports that are in
use:

.. code::

    # tcpdump -ttnr tftp_rrq.pcap
    1367411051.972852 IP 192.168.0.253.50618 > 192.168.0.10.69:  20 RRQ "rfc1350.txtoctet" [tftp]
    1367411052.077243 IP 192.168.0.10.3445 > 192.168.0.253.50618: UDP, length 516
    1367411052.081790 IP 192.168.0.253.50618 > 192.168.0.10.3445: UDP, length 4
    1367411052.086300 IP 192.168.0.10.3445 > 192.168.0.253.50618: UDP, length 516
    1367411052.088961 IP 192.168.0.253.50618 > 192.168.0.10.3445: UDP, length 4
    1367411052.088995 IP 192.168.0.10.3445 > 192.168.0.253.50618: UDP, length 516
    [...]

Turns out that only the first packet is using the well-known TFTP port
69/udp, whereas all the subsequent packets use ephemeral ports. Due to
the port difference, Zeek believes it is seeing two independent
network connections, and it does not associate TFTP with the second
one at all due to its lack of the well-known port (neither does
``tcpdump``!). Zeek's connection log confirms this by showing two
separate entries:

.. code::

    # cat conn.log
    1367411051.972852  CH3xFz3U1nYI1Dp1Dk  192.168.0.253  50618  192.168.0.10  69  udp  spicy_tftp  -  -  -  S0  -  -  0  D  1  48  0  0  -
    1367411052.077243  CfwsLw2TaTIeo3gE9g  192.168.0.10  3445  192.168.0.253  50618  udp  -  0.181558  24795  196  SF  -  -  0  Dd  49  26167  49  1568  -

Switching the ports for subsequent packets is a quirk in TFTP that
resembles similar behaviour in standard FTP, where data connections
get set up separately as well. Fortunately, Zeek provides a built-in
function to designate a specific analyzer for an anticipated future
connection. We can call that function when we see the initial request:

.. literalinclude:: examples/tftp-schedule-analyzer.zeek
    :language: zeek

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt
    # zeek -r tftp_rrq.pcap tftp.hlto tftp.zeek
    TFTP read request, [orig_h=192.168.0.253, orig_p=50618/udp, resp_h=192.168.0.10, resp_p=69/udp], rfc1350.txt, octet
    TFTP data, 1, \x0a\x0a\x0a\x0a\x0a\x0aNetwork Working Group [...]
    TFTP ack, 1
    TFTP data, 2, B Official Protocol\x0a   Standards" for the  [...]
    TFTP ack, 2
    TFTP data, 3, protocol was originally designed by Noel Chia [...]
    TFTP ack, 3
    TFTP data, 4, r mechanism was suggested by\x0a   PARC's EFT [...]
    TFTP ack, 4
    [...]

Now we are seeing all the packets as we would expect.

Zeek Script
-----------

Analyzers normally come along with a Zeek-side script that implements
a set of standard base functionality, such as recording activity into
a protocol specific log file. These scripts provide handlers for the
analyzers' events, and collect and correlate their activity as
desired. We have created such :download:`a script for TFTP
<examples/tftp.zeek>`, based on the events that our Spicy analyzer
generates. Once we add that to the Zeek command line, we will see a
new ``tftp.log``:

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt
    # zeek -r tftp_rrq.pcap tftp.hlto tftp.zeek
    # cat tftp.log
    #fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	wrq	fname	mode	uid_data	size	block_sent	block_acked	error_code	error_msg
    1367411051.972852	CKWH8L3AIekSHYzBU	192.168.0.253	50618	192.168.0.10	69	F	rfc1350.txt	octet	ClAr3P158Ei77Fql8h	24599	49	49	-	-

The TFTP script also labels the second session as TFTP data by
adding a corresponding entry to the ``service`` field inside the
Zeek-side connection record. With that, we are now seeing this in
``conn.log``:

.. code::

    1367411051.972852  ChbSfq3QWKuNirt9Uh  192.168.0.253  50618  192.168.0.10  69  udp  spicy_tftp  -  -  -  S0  -  -0  D  1  48  0  0  -
    1367411052.077243  CowFQj20FHHduhHSYk  192.168.0.10  3445  192.168.0.253  50618  udp  spicy_tftp_data  0.181558  24795  196  SF  --  0  Dd  49  26167  49  1568  -

The TFTP script ends up being a bit more complex than one would expect
for such a simple protocol. That's because it tracks the two related
connections (initial request and follow-up traffic on a different
port), and combines them into a single TFTP transaction for logging.
Since there is nothing Spicy-specific in that Zeek script, we skip
discussing it here in more detail.

.. _zkg_create_package:

Creating a Zeek Package
=======================

We have now assembled all the parts needed for providing a new
analyzer to Zeek. By adding a few further pieces, we can wrap that
analyzer into a full *Zeek package* for others to install easily
through *zkg*. To help create that wrapping, *zkg* provides a template
for instantiating a skeleton analyzer package as a starting point. The
skeleton comes in three different flavors, depending on which kind of
analyzer you want to create: protocol, file, or packet analyzer.
In each case, it creates all the necessary files along with the
appropriate directory layout, and even includes a couple of
standard test cases.

To create the scaffolding for our TFTP analyzer, execute the following
command and provide the requested information::

    # zkg create --features spicy-protocol-analyzer --packagedir spicy-tftp
    "package-template" requires a "name" value (the name of the package, e.g. "FooBar" or "spicy-http"):
    name: spicy-tftp
    "package-template" requires a "analyzer" value (name of the Spicy analyzer, which typically corresponds to the protocol/format being parsed (e.g. "HTTP", "PNG")):
    analyzer: TFTP
    "package-template" requires a "protocol" value (transport protocol for the analyzer to use: TCP or UDP):
    protocol: UDP
    "package-template" requires a "unit_orig" value (name of the top-level Spicy parsing unit for the originator side of the connection (e.g. "Request")):
    unit_orig: Packet
    "package-template" requires a "unit_resp" value (name of the top-level Spicy parsing unit for the responder side of the connection (e.g. "Reply"); may be the same as originator side):
    unit_resp: Packet


The above creates the following files (skipping anything related to
``.git``)::

    spicy-tftp/CMakeLists.txt
    spicy-tftp/COPYING
    spicy-tftp/README
    spicy-tftp/analyzer/CMakeLists.txt
    spicy-tftp/analyzer/tftp.evt
    spicy-tftp/analyzer/tftp.spicy
    spicy-tftp/cmake/FindSpicyPlugin.cmake
    spicy-tftp/scripts/__load__.zeek
    spicy-tftp/scripts/dpd.sig
    spicy-tftp/scripts/main.zeek
    spicy-tftp/testing/Baseline/tests.run-pcap/conn.log
    spicy-tftp/testing/Baseline/tests.run-pcap/output
    spicy-tftp/testing/Baseline/tests.standalone/
    spicy-tftp/testing/Baseline/tests.standalone/output
    spicy-tftp/testing/Baseline/tests.trace/output
    spicy-tftp/testing/Baseline/tests.trace/tftp.log
    spicy-tftp/testing/Files/random.seed
    spicy-tftp/testing/Makefile
    spicy-tftp/testing/Scripts/README
    spicy-tftp/testing/Scripts/diff-remove-timestamps
    spicy-tftp/testing/Scripts/get-zeek-env
    spicy-tftp/testing/Traces/tcp-port-12345.pcap
    spicy-tftp/testing/Traces/udp-port-12345.pcap
    spicy-tftp/testing/btest.cfg
    spicy-tftp/testing/tests/availability.zeek
    spicy-tftp/testing/tests/standalone.spicy
    spicy-tftp/testing/tests/trace.zeek
    spicy-tftp/zkg.meta


Note the ``*.evt``, ``*.spicy``, ``*.zeek`` files: they correspond to
the files we created for TFTP in the preceding sections; we can just
move our versions in there. Furthermore, the generated scaffolding
marks places with ``TODO`` that need manual editing: use ``git grep
TODO`` inside the ``spicy-tftp`` directory to find them. We won't go
through all the specific customizations for TFTP here, but for
reference you can find the full TFTP package as created from the *zkg*
template on `GitHub <https://github.com/zeek/spicy-tftp>`_.

If instead of a protocol analyzer, you'd like to create a file or
packet analyzer, run zkg with ``--features spicy-file-analyzer`` or
``--features spicy-packet-analyzer``, respectively. The generated
skeleton will be suitably adjusted then.

Next Steps
==========

This tutorial provides an introduction to the Spicy language and
toolchain. Spicy's capabilities go much further than what we could
show here. Some pointers for what to look at next:

- :ref:`programming` provides an in-depth discussion of the Spicy
  language, including in particular all the constructs for
  :ref:`parsing data <parsing>` and a :ref:`reference of language
  elements <spicy_language>`. Note that most of Spicy's :ref:`types
  <types>` come with operators and methods for operating on values.
  The :ref:`debugging` section helps understanding Spicy's operation
  if results do not match what you would expect.

- :ref:`examples` summarizes grammars coming with the
  Spicy distribution.

- :ref:`zeek_plugin` discusses Spicy's integration into Zeek.
