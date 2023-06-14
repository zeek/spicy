
.. _getting_started:

Getting Started
===============

The following gives a short overview how to write and use Spicy
parsers. We won't use many of Spicy's features yet, but we we'll walk
through some basic code examples and demonstrate typical usage of the
Spicy toolchain.

Hello, World!
-------------

Here's a simple "Hello, world!" in Spicy:

.. literalinclude:: examples/hello.spicy
   :lines: 4-
   :language: spicy

Assuming that's stored in ``hello.spicy``, you can compile and execute
the code with Spicy's standalone compiler ``spicyc``::

    # spicyc -j hello.spicy
    Hello, world!

``spicyc -j`` compiles the source code into native code on the fly
using your system's C++ compiler, and then directly executes the
result. If you run ``spicyc -c hello.spicy``, you will see the C++
code that Spicy generates behind the scenes.

You can also precompile the code into an object file, and then load
that for immediate execution::

    # spicyc -j -o hello.hlto hello.spicy
    # spicyc -j hello.hlto
    Hello, world!

To compile Spicy code into an actual executable on disk, use
``spicy-build``::

    # spicy-build -o a.out hello.spicy
    # ./a.out
    Hello, world!

``spicy-build`` is a small shell script that wraps ``spicyc -c`` and
runs the resulting code through the system's C++ compiler to produce
an executable.

..  note::

    .. image:: _static/hilti-logo.png
     :align: left
     :width: 50

    Internally, Spicy employs another intermediary language called
    *HILTI* that sits between the Spicy source code and the generated
    C++ output. For more complex Spicy grammars, the HILTI code is
    often far easier to comprehend than the final C++ code, in
    particular once we do some actual parsing.  To see that
    intermediary HILTI code, execute ``spicy -p hello.spicy``. The
    ``.hlto`` extension comes from HILTI as well: It's an
    HILTI-generated object file.

A Simple Parser
---------------

To actually parse some data, we now look at a small example dissecting
HTTP-style request lines, such as: ``GET /index.html HTTP/1.0``.

Generally, in Spicy you define parsers through types called "units"
that describe the syntax of a protocol. A set of units forms a
*grammar*. In practice, Spicy units typically correspond pretty
directly to protocol data units (PDUs) as protocol specifications tend
to define them. In addition to syntax, a Spicy unit type can also
specify semantic actions, called *hooks*, that will execute during
parsing as the corresponding pieces are extracted.

Here's an example of a Spicy script for parsing HTTP request lines:

.. literalinclude:: examples/my-http.spicy
   :lines: 4-
   :caption: my-http.spicy
   :language: spicy

In this example, you can see a number of things that are typical for
Spicy code:

    * A Spicy input script starts with a ``module`` statement defining
      a namespace for the script's content.

    * The layout of a piece of data is defined by creating a ``unit``
      type. The type lists individual *fields* in the order they are
      to be parsed. The example defines two such units:
      ``RequestLine`` and ``Version``.

    * Each field inside a unit has a type and an optional name. The
      type defines how that field will be parsed from raw input data.
      In the example, all fields use regular expressions instead of
      actual data types (``uint32`` would be an actual type), which
      means that the generated parser will match these expressions
      against the input stream. Assuming a match, the corresponding
      value will then be recorded with type ``bytes``, which is
      Spicy's type for binary data. Note how the regular expressions
      can either be given directly as a field's type (as in
      ``Version``), or indirectly via globally defined constants (as
      in ``RequestLine``).

    * If a field has a name, it can later be referenced to access its
      value. Consequently, in this example all fields with semantic
      meanings have names, while those which are unlikely to be
      relevant later do not (e.g., whitespace).

    * A unit field can have another unit as its type; here that's the
      case for the ``version`` field in ``RequestLine``; we say that
      ``Version`` is a *subunit* of ``RequestLine``. The meaning for
      parsing is straight-forward: When parsing the top-level unit
      reaches the field with the subunit, it switches to processing
      that field according to the subunit's definition. Once the
      subunit is fully parsed, the top-level unit's next field is
      processed as normal from the remaining input data.

    * We can specify code to be executed when a unit has been
      completely parsed by implementing a hook called ``%done``.
      Inside the hook's code body, statements can refer to the unit
      instance currently being parsed through an implicitly defined
      ``self`` identifier. Through ``self``, they can then access any
      fields already parsed by using a standard attribute notation
      (``self.<field>``). As the access to ``version`` shows, this
      also works for getting to fields nested inside subunits. In the
      example, we tell the generated parser to print out three of the
      parsed fields whenever a ``RequestLine`` has been fully parsed.

    * The ``public`` keyword exposes the generated parser of a unit to
      to external host applications wanting to deploy it. Only public
      units can be used as the starting point for feeding input;
      non-public subunits cannot be directly instantiated by host
      applications.

Now let us see how we turn this into an actual parser that we can run.
Spicy comes with a tool called ``spicy-driver`` that acts as a
generic, standalone host application for Spicy parsers: It compiles
Spicy scripts into code and then feeds them its standard input as data
to parse. Internally, ``spicy-driver`` uses much of the same machinery
as ``spicyc``, but provides additional code kicking off the actual
parsing as well.

With the above Spicy script in a file ``my-http.spicy``, we can use
``spicy-driver`` on it like this::

    # echo "GET /index.html HTTP/1.0" | spicy-driver my-http.spicy
    GET, /index.html, 1.0

As you see, the ``print`` statement inside the ``%done`` hook wrote
out the three fields as we would expect (``print`` automatically
separates its arguments with commas).  If we pass something into the
driver that's malformed according to our grammar, the parser will
complain::

    # echo "GET XXX/1.0" | spicy-driver my-http.spicy
    [fatal error] terminating with uncaught exception of type spicy::rt::ParseError: parse error: failed to match regular expression (my-http.spicy:7)

Using ``spicy-driver`` in this way relies on Spicy's support for
just-in-time compilation, just like ``spicyc -j``. In the background,
there's C++ code being generated and compiled without that we see it.
Just like in the earlier example, we can also either use ``spicyc`` to
precompile the C++ code into an object file that ``spicy-driver`` can
then load, or use ``spicy-build`` to give us an actual executable::

    # spicyc -j -o my-http.hlto  my-http.spicy
    # echo "GET /index.html HTTP/1.0" | spicy-driver my-http.hlto
    GET, /index.html, 1.0

::

    # spicy-build -o a.out my-http.spicy
    # echo "GET /index.html HTTP/1.0" | ./a.out
    GET, /index.html, 1.0

Spicy also comes with another tool :ref:`spicy-dump <spicy-dump>` that
works similar to ``spicy-driver``, but prints out the parsed fields at
the end, either in a custom ASCII representation or as JSON::

    # echo "GET /index.html HTTP/1.0" | spicy-dump my-http.hlto
    MyHTTP::RequestLine {
        method: GET
        uri: /index.html
        version: MyHTTP::Version {
            number: 1.0
        }
    }

    # echo "GET /index.html HTTP/1.0" | spicy-dump -J my-http.hlto
    {"method":"GET","uri":"/index.html","version":{"number":"1.0"}}

If you want to see the actual parsing code that Spicy generates, use
``spicyc`` again: ``spicyc -c my-http.spicy`` will show the C++ code,
and ``spicyc -p my-http.spicy`` will show the intermediary HILTI code.

Zeek Integration
----------------

Now let's use our ``RequestLine`` parser with Zeek.

Since version 5.0, Zeek comes with Spicy support built-in by default,
so normally you won't need to install anything further to make use of
Spicy parsers. To double check that your Zeek indeed supports Spicy,
confirm that it shows up in the output of ``zeek -N``:

.. code::

    # zeek -N
    <...>
    Zeek::Spicy - Support for Spicy parsers (``*.spicy``, ``*.evt``, ``*.hlto``) (built-in)

If you do not see the Spicy listed, it must have been disabled at Zeek
build time. Assuming Spicy is indeed available, you will also find the
Zeek-side compiler tool ``spicyz`` in the same location as the ``zeek``
binary.

Next, we prepare some input traffic for testing our ``RequestLine``
parser with Zeek.

.. rubric:: Preparations

Because Zeek works from network packets, we first need a packet trace
with the payload we want to parse. We can't just use a normal HTTP
session as our simple parser wouldn't go further than just the first
line of the protocol exchange and then bail out with an error. So
instead, for our example we create a custom packet trace with a TCP
connection that carries just a single HTTP request line as its
payload::

    # tcpdump -i lo0 -w request-line.pcap port 12345 &
    # nc -l 12345 &
    # echo "GET /index.html HTTP/1.0" | nc localhost 12345
    # killall tcpdump nc

This gets us :download:`this trace file <examples/request-line.pcap>`.

.. _example_zeek_my_http_adding_analyzer:

.. rubric:: Adding a Protocol Analyzer

Now we can go ahead and add a new protocol analyzer to Zeek. We
already got the Spicy grammar to parse our connection's payload, it's
in ``my-http.spicy``. In order to use this with Zeek, we have two
additional things to do: (1) We need to let Zeek know about our new
protocol analyzer, including when to use it; and (2) we need to define
at least one Zeek event that we want our parser to generate, so that
we can then write a Zeek script working with the information that it
extracts.

We do both of these by creating an additional control file for Zeek:

.. literalinclude:: examples/my-http.evt
    :caption: my-http.evt
    :linenos:
    :language: spicy-evt

The first block (lines 1-3) tells Zeek that we have a new protocol
analyzer to provide. The analyzer's Zeek-side name is
``spicy::MyHTTP``, and it's meant to run on top of TCP connections
(line 1). Lines 2-3 then provide Zeek with more specifics: The entry
point for originator-side payload is the ``MyHTTP::RequestLine`` unit
type that our Spicy grammar defines (line 2); and we want Zeek to
activate our analyzer for all connections with a responder port of
12345 (which, of course, matches the packet trace we created).

The second block (line 5) tells Zeek that we want to
define one event. On the left-hand side of that line we give the unit
that is to trigger the event. The right-hand side defines its name and
arguments. What we are saying here is that every time a ``RequestLine``
line has been fully parsed, we'd like a ``MyHTTP::request_line`` event
to go to Zeek. Each event instance will come with four parameters:
Three of them are the values of corresponding unit fields, accessed
just through normal Spicy expressions (inside an event argument
expression, ``self`` refers to the unit instance that has led to the
generation of the current event). The first parameter, ``$conn``, is a
"magic" keyword that passes the Zeek-side
connection ID (``conn_id``) to the event.

Now we got everything in place that we need for our new protocol
analyzer---except for a Zeek script actually doing something with the
information we are parsing. Let's use this:

.. literalinclude:: examples/my-http.zeek
    :caption: my-http.zeek
    :language: zeek

You see an Zeek event handler for the event that we just defined,
having the expected signature of four parameters matching the types of
the parameter expressions that the ``*.evt`` file specifies. The
handler's body then just prints out what it gets.

.. _example_zeek_my_http:

Finally we can put together our pieces by compiling the Spicy grammar and the
EVT file into an HLTO file with ``spicyz``, and by pointing Zeek at the produced
file and the analyzer-specific Zeek scripts::

    # spicyz my-http.spicy my-http.evt -o my-http.hlto
    # zeek -Cr request-line.pcap my-http.hlto my-http.zeek
    Zeek saw from 127.0.0.1: GET /index.html 1.0

When Zeek starts up here the Spicy integration registers a protocol analyzer to
the entry point of our Spicy grammar as specified in the EVT file. It then
begins processing the packet trace as usual, now activating our new analyzer
whenever it sees a TCP connection on port 12345. Accordingly, the
``MyHTTP::request_line`` event gets generated once the parser gets to process
the session's payload. The Zeek event handler then executes and prints the
output we would expect.

.. note::

    By default, Zeek suppresses any output from Spicy-side
    ``print`` statements. You can add ``Spicy::enable_print=T`` to the
    command line to see it. In the example above, you would then get
    an additional line of output: ``GET, /index.html, 1.0``.

Custom Host Application
-----------------------

Spicy parsers expose a C++ API that any application can leverage to
send them data for processing. The specifics of how to approach this
depend quite a bit on the particular needs of the application (Is it
just a single, static parser that's needed; or a set not known
upfront, and compiled dynamically? Just a single input stream, or
many? All data in one buffer, or coming in incrementally? How does the
application want to access the parsed information?). That said, the
most basic use case is quite straight-forward: feeding data into a
specific parser. Here's a small C++ program that parses input with our
``RequestLine`` parser:

.. literalinclude:: examples/my-http.cc
    :caption: my-http.cc
    :language: c++

.. code::

    # spicy-build -S -o a.out my-http.cc my-http.spicy
    # echo "GET /index.html HTTP/1.0" | ./a.out
    GET, /index.html, 1.0
    # echo 'Hello, World!' | ./a.out
    parse error: failed to match regular expression (my-http.spicy:7)

We are using ``-S`` with ``spicy-build`` because we're providing our
own ``main`` function.

The code in ``my-http.cc`` is the core of what ``spicy-driver`` does
if we ignore the dynamic JIT compilation. See :ref:`host_applications`
for more.
