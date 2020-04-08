
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

Assuming that's stored in ``hello.spicy`` and you built Spicy with JIT
support, you can compile and execute the code with Spicy's standalone
compiler ``spicyc``::

    # spicyc -j hello.spicy
    Hello, world!

``spicyc -j`` compiles the source code into native code on the fly,
and then directly executes the result. If you run ``spicyc -c
hello.spicy``, you will see the C++ code that Spicy generates behind
the scenes.

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

    Internally, Spicy employs another intermediary language
    called *HILTI*. HILTI sits between the Spicy source code and the
    generated C++ output. For more complex Spicy grammars, the HILTI
    code is often far easier to comprehend than the final C++ code.
    To output intermediary HILTI code, execute ``spicyc -p hello.spicy``.
    The ``.hlto`` extension stems from HILTI as well: It's a
    HILTI-generated object file.

A Simple Parser
---------------

In the following, we present a small parser to dissect a HTTP-style
request line, such as: ``GET /index.html HTTP/1.0``.

Generally, in Spicy you define parsers through types called *units*
that describe the syntax of a protocol. A set of units forms a
*grammar*. In practice, Spicy units typically correspond
to protocol data units (PDUs) as protocol specifications tend
to define them. In addition to syntax, a Spicy unit can also
specify semantic actions, called *hooks*, that will execute
during parsing as the corresponding pieces are extracted.

Here's an example of a Spicy script for parsing HTTP request lines:

.. literalinclude:: examples/my-http.spicy
   :lines: 4-
   :caption: my-http.spicy

In this example, you can see a number of things that are typical for
Spicy code:

    * A Spicy input script starts with a ``module``
      statement defining the namespace for the script's content.

    * The layout of a piece of data is defined by creating a ``unit``
      type. The type lists individual *fields* in the order they are
      to be parsed. In the example, two units are defined:
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

    * If a field has a name, it can later be referenced to access
      its value. Consequently, in this example all fields with
      semantic meaning have names, while those which are
      unlikely to be relevant do not (e.g., whitespace).

    * A field can have another unit as its type; here that's the
      case for the ``version`` field in ``RequestLine``; we say that
      ``Version`` is a *subunit* of ``RequestLine``. The meaning for
      parsing is straight-forward: When reaching a field with a subunit,
      parsing switches to process that field according to its subunit.
      Once parsing of the subunit completed, it continues
      at the previous unit's next field with the remaining input data.

    * We can specify code to be executed when a unit has been
      completely parsed by implementing a hook called ``%done``.
      Inside the hook's code body, statements can refer to the unit
      instance currently being parsed through an implicitly defined
      ``self`` identifier. Through ``self``, already parsed fields
      can be accessed using standard attribute notation
      (``self.<field>``). As the access to ``self.version.number`` shows,
      this also works for fields nested inside subunits. In the given
      example, the generated parser prints out three of the
      parsed fields whenever a ``RequestLine`` has been fully parsed.

    * The ``public`` keyword exposes the generated parser of a unit
      to external host applications.
      Only public units can be used as an entry point for feeding
      input data; non-public subunits cannot be directly instantiated
      from host applications.

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

As shown, the ``print`` statement inside the ``%done`` hook prints
the three fields as we would expect (``print`` automatically
separates its arguments with commas).  If we pass malformed input to
the driver, the parser complains::

    # echo "GET XXX/1.0" | spicy-driver request.spicy
    [fatal error] terminating with uncaught exception of type spicy::rt::ParseError: parse error: failed to match regular expression (my-http.spicy:7)

Using ``spicy-driver`` in this way relies on Spicy's support for
just-in-time compilation, just like ``spicyc -j``. Behind the curtains,
HILTI and C++ code is generated and compiled. As presented earlier,
we can also precompile the parser into an object file using ``spicyc``
and execute the object file with ``spicy-driver``::

    # spicyc -j -o my-http.hlto  my-http.spicy
    # echo "GET /index.html HTTP/1.0" | spicy-driver my-http.hlto
    GET, /index.html, 1.0


Alternatively, ``spicy-build`` can produce an executable file
that can be run directly::

    # spicy-build -o a.out my-http.spicy
    # echo "GET /index.html HTTP/1.0" | ./a.out -p MyHTTP::RequestLine
    GET, /index.html, 1.0


To inspect the generated parsing code, run ``spicyc -c my-http.spicy``
to output the generated C++ code and ``spicyc -p my-http.spicy`` to
output HILTI intermediary code.


Zeek Integration
----------------

Now let's use our ``RequestLine`` parser with Zeek. For that we first
need to prepare some input, and get Zeek to load the required Spicy
plugin. Then we can use the grammar that we already got to add a new
protocol analyzer to Zeek.

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

Next, we need to tell Zeek to load a Spicy plugin. If your Spicy build
has found Zeek during its ``configure`` run, it will have already
compiled and installed the plugin into Zeek's system-wide plugin
directory. You can confirm that with ``zeek -N``::

    # zeek -N
    <...>
    Zeek::Spicy - Support for Spicy parsers (*.spicy, *.evt) (dynamic, version 0.3.0)

As you can see, Zeek now reports the Spicy plugin as available among
all the other plugins that it has already built-in.

If you don't see the Spicy plugin in there, the installation might not
have had permission to write into the Zeek plugin directory. See
:ref:`zeek_installation` for how to point Zeek to the right location
manually.

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

The first block (lines 1-3) tells Zeek that we have a new protocol
analyzer to provide. The analyzer's Zeek-side name is
``spicy::MyHTTP``, and it's meant to run on top of TCP connections
(line 1). Lines 2-3 then provide Zeek with more specifics: The entry
point for originator-side payload is the ``MyHTTP::RequestLine`` unit
type that our Spicy grammar defines (line 2); and we want Zeek to
activate our analyzer for all connections with a responder port of
12345 (which, of course, matches the packet trace we created).

The second block (line 5) tells the Spicy plugin that we want to
define one event. On the left-hand side of that line we give the unit
that is to trigger the event. The right-hand side defines its name and
arguments. What we are saying here is that every time a ``RequestLine``
line has been fully parsed, we'd like a ``MyHTTP::request_line`` event
to go to Zeek. Each event instance will come with four parameters:
Three of them are the values of corresponding unit fields, accessed
just through normal Spicy expressions (inside an event argument
expression, ``self`` refers to the unit instance that has led to the
generation of the current event). The first parameter, ``$conn``, is a
"magic" keyword that lets the Spicy plugin pass the Zeek-side
connection ID (``conn_id``) to the event.

Now we got everything in place that we need for our new protocol
analyzer---except for a Zeek script actually doing something with the
information we are parsing. Let's use this:

.. literalinclude:: examples/my-http.zeek
    :caption: my-http.zeek

You see an Zeek event handler for the event that we just defined,
having the expected signature of four parameters matching the types of
the parameter expressions that the ``*.evt`` file specifies. The
handler's body then just prints out what it gets.

.. _example_zeek_my_http:

Finally we can put together our pieces by pointing Zeek to all the
files we got::

    # zeek -Cr request-line.pcap my-http.spicy my-http.evt my-http.zeek
    GET, /index.html, 1.0
    Zeek saw from 127.0.0.1: GET /index.html 1.0

When Zeek starts up here, it passes any ``*.spicy`` and ``*.evt`` on
to the Spicy plugin, which then first kicks off all of its code
generation. Afterwards the plugin registers the new analyzer with the
Zeek event engine. Zeek then begins processing the packet trace as
usual, now activating our new analyzer whenever it sees a TCP
connection on port 12345. Accordingly, the ``MyHTTP::request_line``
event gets generated once the parser gets to process the session's
payload. The Zeek event handler then executes and prints the output we
would expect. (Note how we are in fact getting *two* lines of output:
The first line is still from the Spicy-side ``print`` statement inside
the ``RequestLine`` unit. One would normally remove that statement at
this point.)

If you tried the above, you will have noticed that Zeek took a little
while to start up. That's of course because we're compiling C++ code
in the background again before any packet processing can even begin.
To accelerate the startup, we can once more precompile our analyzer
similar to what we did before with ``spicyc``. We'll use a different
tool for that here, though: ``spicyz`` is a small shell wrapper around
Zeek itself that activates a dedicated precompilation mode for the
Spicy plugin. We give ``spicyz`` (1) an output ``*.hlto`` file to
write the compiled analyzer into; and (2) the ``*.spicy`` and
``*.evt`` inputs that we handed to Zeek above::

    # spicyz -o my-http-analyzer.hlto my-http.spicy my-http.evt
    # zeek -Cr request-line.pcap my-http-analyzer.hlto my-http.zeek
    GET, /index.html, 1.0
    Zeek saw from 127.0.0.1: GET /index.html 1.0

That ``zeek`` execution is now happening instantaneously.

Custom Host Application
-----------------------

Spicy parsers expose a C++ API that any application can leverage to
parse input data. The specifics of how to approach this
depend quite a bit on the particular needs of the application.
However, the most basic use-case of feeding a single input stream into
a specific parser is straight-forward. This is presented in the following
small C++ program that parses input from ``stdin`` with our
``RequestLine`` parser:

.. literalinclude:: examples/my-http.cc
    :caption: my-http.cc

.. code::

    # spicy-build -o a.out my-http.cc my-http.spicy
    # echo "GET /index.html HTTP/1.0" | ./a.out
    GET, /index.html, 1.0
    # echo 'Hello, World!' | ./a.out
    parse error: failed to match regular expression (my-http.spicy:7)

The code in ``my-http.cc`` is indeed the core of what ``spicy-driver``
does, if we ignore the dynamic JIT compilation.

More advanced host application need to consider some of the following
questions:

* Does the application use a single static parser, a set of known parsers,
  or dynamically compiled parsers?
* Is there a single input stream or multiple input streams?
* Is incremental parsing required, or is all data available at once?
* How does the application want access the parsed information?

.. note::

    Some additional pointers for application developers:

    - ``my-http.cc`` is a very stripped down version of Spicy's driver
      code installed into
      ``share/spicy/spicy-driver-host.cc``. This code is compiled into
      an executable when running ``spicy-build`` as we did above.
      If you look at ``spicy-driver-host.cc``, among other
      things you'll also see how to dynamically query the runtime
      system for available parsers.

    - The code for the main ``spicy-driver`` tool is quite similar as
      well, and in addition shows how to dynamically compile Spicy
      parsers just-in-time.
