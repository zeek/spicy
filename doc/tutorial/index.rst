
.. _tutorial:

=========================
Tutorial: A Real Analyzer
=========================

In this chapter we will develop a simple protocol analyzer from
scratch. Our analyzer will parse the
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
packet at a time. While TFTP is running on top of UDP, we will
Spicy parse just the actual UDP
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
      we can express directly as such in Spicy: the ``filename`` field
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
    :exec: printf '\000\001rfc1350.txt\000octet\000' | spicy-driver -d %INPUT
    :show-with: tftp.spicy

Here, ``spicy-driver`` compiles our ``ReadRequest`` unit into an
executable parser and then feeds it with the data it is receiving on
standard input. The output of ``spicy-driver`` is the result of our
``print`` statement executing at the end.

.. _testing-with-batch-mode:

What would we do with a more complex protocol where we cannot easily
use ``printf`` to create some dummy payload? We would probably have
access to some protocol traffic in pcap traces, however we can't just
feed those into ``spicy-driver`` directly as they will contain all the
other network layers as well that our grammar does not handle (e.g.,
IP and UDP). One way to test with a trace would be proceeding with
Zeek integration at this point, so that we could let Zeek strip off
the lower layers and then feed our parser only the TFTP application
payload. However, during development it is often easier to avoid
Zeek's additional complexity at first, and stay with ``spicy-driver``
until the protocol parsing is mostly in place.

To facilitate that, ``spicy-driver`` offers a :ref:`batch mode
<spicy-driver-batch>`, which allows feeding connection-based,
bi-directional packet payloads into a parser, just as Zeek (or any
other network application) would do after stripping off the lower
layers. In this mode, ``spicy-driver`` reads input from a
specially-crafted batch file that retains the packet structure of the
underlying network communication as well as (just) the payload data
that we want parse.

To create such a batch input file, we can leverage Zeek itself: it
comes with a corresponding script that turns any PCAP trace into a
``spicy-driver`` batch file. Let's use that script with a tiny TFTP
trace, ``tftp_rrq.pcap``, borrowed from `Wireshark's pcap archive
<https://wiki.wireshark.org/SampleCaptures#tftp>`_. First, we confirm
with ``tcpdump`` that the trace contains a single file download:

.. code::

    # tcpdump -ttnr tftp_rrq.pcap
    1367411051.972852 IP 192.168.0.253.50618 > 192.168.0.10.69:  20 RRQ "rfc1350.txtoctet" [\|tftp]
    1367411052.077243 IP 192.168.0.10.3445 > 192.168.0.253.50618: UDP, length 516
    1367411052.081790 IP 192.168.0.253.50618 > 192.168.0.10.3445: UDP, length 4
    [...]

We now run Zeek on that trace to perform the batch conversion:

.. code::

    # zeek -r tftp_rrq.pcap policy/frameworks/spicy/record-spicy-batch SpicyBatch::filename=tftp_rrq.dat
    tracking [orig_h=192.168.0.253, orig_p=50618/udp, resp_h=192.168.0.10, resp_p=69/udp]
    tracking [orig_h=192.168.0.10, orig_p=3445/udp, resp_h=192.168.0.253, resp_p=50618/udp]
    recorded 2 sessions total
    output in tftp_rrq.dat

This leaves a new ``spicy-driver`` batch file in ``tftp_rrq.dat`` (if
we had left off the ``SpicyBatch::filename`` argument, the default
output name is ``batch.dat``).

Now we can pass that batch file into ``spicy-driver``:

.. spicy-output:: rrq.spicy 2
    :exec: spicy-driver -d -F tutorial/examples/tftp_rrq.dat -P 69/udp%orig=TFTP::ReadRequest %INPUT
    :show-as: spicy-driver -d -F tftp_rrq.dat -P 69/udp%orig=TFTP::ReadRequest tftp.spicy

The one additional piece here is that we need to tell ``spicy-driver``
on which packets inside the batch file to deploy our parser (because,
in principle, the batch could contain many different protocols
distributed over independent connections). We achieve that through
``-P 69/udp%orig=TFTP::ReadRequest``, which specifies that we want to
use the ``TFTP::ReadRequest`` on all originator-side UDP packets for
any connections on port ``69/udp``. See :ref:`spicy-driver
documentation <spicy-driver-batch>` for more on that syntax.

.. note::

    .. versionadded:: 1.13 parser aliases

    That option ``-P`` (aka ``--parser-alias``) is a feature added to
    Spicy in version 1.13. An alternative to using that option---which
    works with older Spicy version as well---is providing a
    :ref:`%port <unit_meta_data>` property inside the
    ``TFTP::ReadRequest`` unit; the two mechanisms have the
    same effect.

Altogether, this gives us an easy way to test our TFTP parser with
actual packet data, without needing to switch to full Zeek integration
yet.

The batch mode  of ``spicy-driver`` is generally worth keeping in mind
while developing a new analyzer: even if the eventual goal is to
create a Zeek analyzer, it is usually easier to work with
``spicy-driver`` for as long as possible before transitioning to the
Zeek-side glue layer later. The same observation applies to debugging:
tracking down why a parser isn't quite doing what you would expect is
normally quicker with Zeek out of the picture. You can even *craft*
input for ``spicy-driver`` manually if you need to test specific edge
cases, for example by simply editing the payload data inside an
existing batch file, tweaking it the way you need it.


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
    :exec: spicy-driver -d -F tutorial/examples/tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet %INPUT
    :show-as: spicy-driver -d -F tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet tftp.spicy
    :max-lines: 6

As you see, we now use ``-P 69/udp=TFTP::Packet`` because we no longer
need to worry about the direction: from now on, the same ``Packet``
unit handles both originator and responder sides. However, because the
way TFTP works, we need an additional parser mapping for the data
connection that's part of the PCAP as well, because that happens on a
different port: ``-P 50618/udp=TFTP::Packet``. The handling of such
dynamic, non-standard ports is something that normally the host
application (e.g., Zeek) would handle on its side. With
``spicy-driver``, we need to do it manually ourselves.

With this in place we now, in fact, see output for all the packets
that the original PCAP contains.

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
    :exec: spicy-driver -d -F tutorial/examples/tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet %INPUT
    :show-as: spicy-driver -d -F tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet tftp.spicy
    :max-lines: 6

However, this does not help us much yet: it still resembles our
original version in that it continues to hardcode one specific packet
type. Indeed, we are now getting error messages for packets of other
opcodes because we told ``spicy-driver`` to use ``Packet`` for them as
well, even though our current definition of ``Packet`` cannot actually
parse them successfully.

But the direction of using sub-units remains promising, we only need
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
    :exec: spicy-driver -d -F tutorial/examples/tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet %INPUT
    :show-as: spicy-driver -d -F tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet tftp.spicy
    :max-lines: 6

The ``self`` keyword always refers to the unit instance currently
being parsed, and we use that to get to the opcode for switching on.
If it is ``1``, we descend down into a Read Request. We are still
getting error messages for other opcodes, but now ``spicy-driver`` is
no longer complaining that it can't parse it them as a Read Request.
Instead, we're rightfully being told that our ``switch`` statement
doesn't provide the alternatives for other opcodes yet.

Of course, it is now easy to add more unit types for handling other
opcodes. Let's start with acknowledgments:

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
    :exec: spicy-driver -d -F tutorial/examples/tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet %INPUT
    :show-as: spicy-driver -d -F tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet tftp.spicy
    :max-lines: 6

As expected, the output shows that for opcode 4, our TFTP parser now
descends into the ``ack`` field while leaving ``rrq`` unset. Now
opcode 3 is the only one remaining in our input that is not handled
yet, hence the remaining error messages.

In total, TFTP defines three more opcodes for other packet types:
``2`` is a Write Request, ``3`` is file data being sent, and ``5`` is
an error. Let's add these to our grammar as well, so that we get the
whole protocol covered (please refer to the RFC for specifics of each
opcode type):

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

.. spicy-output:: tftp-complete-1.spicy
    :exec: spicy-driver -d -F tutorial/examples/tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet %INPUT
    :show-as: spicy-driver -d -F tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet tftp.spicy
    :max-lines: 6

Now we are finally error-free.

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
    :exec: spicy-driver -d -F tutorial/examples/tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet %INPUT
    :show-as: spicy-driver -d -F tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet tftp.spicy
    :max-lines: 6

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
read or a write operation. For a potential Zeek integration later it will be
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
    :exec: spicy-driver -d -F tutorial/examples/tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet %INPUT
    :show-as: spicy-driver -d -F tftp_rrq.dat -P 69/udp=TFTP::Packet -P 50618/udp=TFTP::Packet tftp.spicy
    :max-lines: 6

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

.. literalinclude:: /_static/tftp-no-accept.spicy
    :language: spicy

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

- Zeek's :zeek:`Spicy tutorial <devel/spicy/tutorial.html>` continues
  the TFTP example by turning the Spicy code developed here into
  a full Zeek analyzer.

- :ref:`zeek_plugin` discusses Spicy's integration into Zeek.
