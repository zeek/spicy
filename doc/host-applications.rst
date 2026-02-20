
.. _host_applications:

========================
Custom Host Applications
========================

Spicy provides a C++ API for integrating its parsers into custom host
applications. There are two different approaches to doing this:

1. If you want to integrate just one specific kind of parser, Spicy
   can generate C++ prototypes for it that facilitate feeding data and
   accessing parsing results.

2. If you want to write a generic host application that can support
   arbitrary parsers, Spicy provides a dynamic runtime introspection
   API for dynamically instantiating parsers and accessing results.

We discuss both approaches in the following.

.. note::

    Internally, Spicy is a layer on top of an intermediary framework
    called HILTI. It is the HILTI runtime library that implements most
    of the functionality which we'll look at in this section, so you'll see
    quite a bit of HILTI-side functionality. Spicy comes with a small
    additional runtime library of its own that adds anythings that's
    specific to the parsers it generates.

.. note::

    The API for host applications isn't considered stable at this time
    and specifics may change in future versions of HILTI/Spicy without
    any migration/deprecation process.

.. _host_applications_specific:

Integrating a Specific Parser
=============================

We'll use our simple HTTP example from the :ref:`getting_started`
section as a running example for a parser we want to leverage from a
C++ application.

.. literalinclude:: examples/my_http.spicy
   :lines: 4-
   :caption: my_http.spicy
   :language: spicy

First, we'll use :ref:`spicyc` to generate a C++ parser from the Spicy
source code::

    # spicyc -x my_http my_http.spicy

The option ``-x`` (aka ``--output-c++-files``) tells ``spicyc`` that
we want it to generate C++ code for external compilation, rather than
directly turning the Spicy module into executable code. This generates
two C++ files that have their names prefixed with ``my_http_``::

    # ls my_http_*.cc
    my_http___linker__.cc  my_http_MyHTTP.cc

We don't need to worry further what's in these files.

Next, ``spicyc`` can generate C++ prototypes for us that declare (1) a
set of parsing functions for feeding input into our parser, and (2) a
``struct`` type providing access to the parsed fields. That's done
through option ``-P`` (aka ``--output-prototypes``)::

    # spicyc -P my_http my_http.spicy -o my_http.h

That'll leave the prototypes in ``my_http.h``. The content of that
generated header file tends to be a bit convoluted because it
(necessarily) also contains a bunch of Spicy internals. But stripped
down to the interesting parts, it looks like this for our example:

.. literalinclude:: examples/my_http-excerpt.h

You can see the ``struct`` definition corresponding to the public unit
type, as well as a set of parsing functions with three different
signatures:

``parse1``
    The simplest form of parsing function receives a stream of input
    data, along with an optional view into the stream to limit the
    region to parse if desired and an optional context.
    ``parse1`` will internally instantiate an instance of the unit's
    ``struct``, and then feed the unit's parser with the data stream.
    However, it won't provide access to what's being parsed as it
    doesn't pass back the ``struct``.

``parse2``
    The second form takes a pre-instantiated instance of the unit's
    ``struct`` type, which parsing will fill out. Once parsing
    finishes, results can be accessed by inspecting the ``struct``
    fields.

``parse3``
    The third form takes a pre-instantiated instance of a generic,
    type-erased unit type that the parsing will fill out. Accessing
    the data requires use of HILTI's reflection API, which we will
    discuss in :ref:`host_applications_generic`.

Spicy puts all these declarations into a namespace ``hlt_PREFIX``,
where ``PREFIX`` is the argument we specified to ``-P``. (If you leave
the ``PREFIX`` empty (``spicyc -P ''``), you get a namespace of just
``hlt::*``.)

Let's start by using ``parse1()``:

.. literalinclude:: examples/my_http-host-parse1.cc
   :caption: my_http-host.cc
   :lines: 10-36
   :language: c++

This code first instantiates a stream from data giving on the command
line. It freezes the stream to indicate that no further data will
arrive later. Then it sends the stream into the ``parse1()`` function
for processing.

We can now use the standard C++ compiler to build all this into an
executable, leveraging ``spicy-config`` to add the necessary flags
for finding includes and libraries::

    # clang++ -o my_http my_http-host.cc my_http___linker__.cc my_http_MyHTTP.cc $(spicy-config --cxxflags --ldflags)
    # ./my_http $'GET index.html HTTP/1.0\n'
    GET, /index.html, 1.0

The output comes from the execution of the ``print`` statement inside
the Spicy grammar, demonstrating that the parsing proceeded as
expected.

.. note::

    Above, when building the executable, we used ``clang++`` assuming
    that that's the C++ compiler in use on the system. Generally, you
    need to use the same compiler here as the one that Spicy itself
    got build with, to ensure that libraries and C++ ABI match. To
    ensure that you're using the the right compiler (e.g., if there
    are multiple on the system, or if it's not in ``PATH``),
    :ref:`spicy-config` can print out the full path to the expected
    one through its ``--cxx`` option. You can even put that directly
    into the build command line::

        # $(spicy-config --cxx) -o my_http my_http-host.cc my_http___linker__.cc my_http_MyHTTP.cc $(spicy-config --cxxflags --ldflags)

When using ``parse1()`` we don't get access to the parsed information.
If we want that, we can use ``parse2()`` instead and provide it with a
``struct`` to fill in:

.. literalinclude:: examples/my_http-host-parse2.cc
   :caption: my_http-host.cc
   :lines: 10-45
   :emphasize-lines: 19-28
   :language: c++

::

    # clang++ -o my_http my_http-host.cc my_http___linker__.cc my_http_MyHTTP.cc $(spicy-config --cxxflags --ldflags)
    # ./my_http $'GET index.html HTTP/1.0\n'
    GET, /index.html, 1.0
    method : GET
    uri    : /index.html
    version: 1.0

Another approach to retrieving field values goes through Spicy hooks
calling back into the host application. That's how Zeek's Spicy support
operates. Let's say we want to execute a custom C++ function every
time a ``RequestList`` has been parsed. By adding the following code
to ``my_http.spicy``, we (1) declare that function on the Spicy-side,
and (2) implement a Spicy hook that calls it:

.. literalinclude:: examples/my_http-host-callback.cc
   :caption: my_http.spicy
   :start-after: doc-start-callback-spicy
   :end-before: doc-end-callback-spicy
   :language: spicy

The ``&cxxname`` attribute for ``got_request_line`` indicates to Spicy
that this is a function implemented externally inside custom C++ code,
accessible through the given name. Now we need to implement that
function:

.. literalinclude:: examples/my_http-host-callback.cc
   :caption: my_http-callback.cc
   :start-after: doc-start-callback-cc
   :end-before: doc-end-callback-cc
   :language: c++

Finally, we compile it altogether like before, but now including our
additional custom C++ file::

    # spicyc -x my_http my_http.spicy
    # spicyc -P my_http my_http.spicy -o my_http.h
    # clang++ -o my_http my_http-callback.cc my_http-host.cc my_http___linker__.cc my_http_MyHTTP.cc $(spicy-config --cxxflags --ldflags)
    # ./my_http $'GET index.html HTTP/1.0\n'
    In C++ land: GET, index.html, 1.0
    GET, index.html, 1.0

Note that the C++ function signature needs to match what Spicy
expects, based on the Spicy-side prototype. If you are unsure how
Spicy arguments translate into C++ arguments, look at the C++
prototype that's included for the callback function in the output of
``-P``.

When interfacing with Spicy-generated parsers from custom C++ code,
keep in mind that by default the Spicy optimizer may apply aggressive
optimizations that modify externally visible types and functions based
on their actual use inside the Spicy code. If you want to rely on a
stable C++ API for the generated parser, you can disable these
optimizations by passing ``--strict-public-api`` to the compiler.
Alternatively (and preferably), you can leverage the generic runtime
introspection facilities described in the next section, which will
always reflect the parser's functionality after any optimizations. See
:ref:`optimization` for more details on Spicy's optimizations and how
they affect the public API.

.. _host_applications_generic:

Supporting Arbitrary Parsers
============================

This approach is more complex, and we'll just briefly describe the
main pieces here. All of the tools coming with Spicy support arbitrary
parsers and can serve as further examples (e.g., :ref:`spicy-driver`,
:ref:`spicy-dump`, :ref:`zeek_plugin`). Indeed, they all
build on the same C++ library class ``spicy::rt::Driver`` that
provides a higher-level API to working with Spicy's parsers in a
generic fashion. We'll do the same in the following.

Retrieving Available Parsers
----------------------------

The first challenge for a generic host application is that it cannot
know what parsers are even available. Spicy's runtime library provides
an API to get a list of all parsers that are compiled into the current
process. Continuing to use the ``my_http.spicy`` example, this code
prints out our one available parser:

.. literalinclude:: examples/my_http-host-driver.cc
   :caption: my_http-host.cc
   :lines:   9-14,31-44,59-64
   :language: c++

::

    # clang++ -o my_http my_http-host.cc my_http___linker__.cc  my_http_MyHTTP.cc $(spicy-config --cxxflags --ldflags)
    # ./my_http
    Available parsers:

        MyHTTP::RequestLine

Using the name of the parser (``MyHTTP::RequestLine``) we can
instantiate it from C++, and then feed it data:

.. literalinclude:: examples/my_http-host-driver.cc
   :lines:   44-53
   :language: c++

::

    # clang++ -o my_http my_http-host.cc my_http___linker__.cc  my_http_MyHTTP.cc $(spicy-config --cxxflags --ldflags)
    # ./my_http $'GET index.html HTTP/1.0\n'
    GET, /index.html, 1.0

That's the output of the ``print`` statement once more.

``unit`` is of type ``spicy::rt::ParsedUnit``, which is a type-erased
class holding, in this case, an instance of
``_hlt::MyHTTP::RequestLine``. Internally, that instance went through
the ``parse3()`` function that we have encountered in the previous
section. To access the parsed fields, there's a visitor API to iterate
generically over HILTI types like this unit:

.. literalinclude:: examples/my_http-host-driver.cc
   :lines: 15-30
   :language: c++

Adding ``print(unit->value())`` after the call to ``processInput()``
then gives us this output:

::

    # clang++ -o my_http my_http-host.cc my_http___linker__.cc  my_http_MyHTTP.cc $(spicy-config --cxxflags --ldflags)
    # ./my_http $'GET index.html HTTP/1.0\n'
    GET, /index.html, 1.0
    method: GET
    uri: /index.html
    version: number: 1.0

Our visitor code implements just what we need for our example. The
source code of ``spicy-dump`` shows a full implementation covering all
available types.

So far we have compiled the Spicy parsers statically into the
generated executable. The runtime API supports loading them
dynamically as well from pre-compiled ``HLTO`` files through the class
``hilti::rt::Library``. Here's the full example leveraging that,
taking the file to load from the command line:

.. literalinclude:: examples/my_http-host-driver-hlto.cc
    :caption: my-driver.cc
    :lines: 9-70
    :emphasize-lines: 27-31
    :language: c++

::

    # clang++ -o my-driver my-driver.cc $(spicy-config --cxxflags --ldflags --dynamic-loading)
    # spicyc -j -o my_http.hlto my_http.spicy
    # printf "GET /index.html HTTP/1.0\n\n<dummy>" > data
    # ./my-driver my_http.hlto MyHTTP::RequestLine "$(cat data)"
    Available parsers:

        MyHTTP::RequestLine

    GET, /index.html, 1.0
    method: GET
    uri: /index.html
    version: number: 1.0

.. note::

    Note the addition of ``--dynamic-loading`` to the ``hilti-config``
    command line. That's needed when the resulting binary will
    dynamically load precompiled Spicy parsers because linker flags
    need to be slightly adjusted in that case.

API Documentation
=================

We won't go further into details of the HILTI/Spicy runtime API here.
Please see :ref:`doxygen` for more on that, the namespaces
``hilti::rt`` and ``spicy::rt`` cover what's available to host
applications.

Our examples always passed the full input at once. You don't need to
do that, Spicy's parsers can process input incrementally as it comes
in, and return back to the caller to retrieve more. See the source of
:repo:`spicy::Driver::processInput() <spicy/runtime/src/driver.cc>`
for an example of how to implement that.
