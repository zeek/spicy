
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
    of the functionality we'll look at in this section, so you'll see
    quite a bit of HILTI-side functionality. Spicy comes with a small
    additional runtime library of its own that adds anythings that's
    specific to the parsers it generates.

.. note::

    The API for host applications is still in flux, and some parts
    aren't the prettiest yet. Specifics of this may change in future
    versions of HILTI/Spicy.

.. _host_applications_specific:

Integrating a Specific Parser
=============================

We'll use our simple HTTP example from the :ref:`getting_started`
section as a running example for a parser we want to leverage from a
C++ application.

.. literalinclude:: examples/my-http.spicy
   :lines: 4-
   :caption: my-http.spicy
   :language: spicy

First, we'll use :ref:`spicyc` to generate a C++ parser from the Spicy
source code::

    # spicyc -c -g my-http.spicy -o my-http.cc

Option ``-c`` (aka ``--output-c++``) tells ``spicyc`` that we want it
to generate C++ code (rather than compiling everything down into
executable code).

Option ``-g`` (aka ``--disable-optimizations``) tells ``spicyc`` to not perform
global optimizations. Optimizations are performed on all modules passed to a
invocation of ``spicyc`` and can remove e.g., unused code. Since we generate
output files with multiple invocations, optimizations could lead to incomplete
code.

We also need ``spicyc`` to get generate some additional additional
"linker" code implementing internal plumbing necessary for
cross-module functionality. That's what ``-l`` (aka
``--output-linker``) does::

    # spicyc -l -g my-http.cc -o my-http-linker.cc

We'll compile this linker code along with the ``my-http.cc``.

Next, ``spicyc`` can also generate C++ prototypes for us that declare
(1) a set of parsing functions for feeding in data, and (2) a
``struct`` type providing access to the parsed fields::

    # spicyc -P -g my-http.spicy -o my-http.h

The output of ``-P`` (aka ``--output-prototypes``) is a bit convoluted
because it (necessarily) also contains a bunch of Spicy internals.
Stripped down to the interesting parts, it looks like this for our
example:

.. literalinclude:: examples/my-http-excerpt.h

.. todo:: The ``struct`` declarations should move into the public
   namespace.

You can see the ``struct`` definitions corresponding to the two unit
types, as well as a set of parsing functions with three different
signatures:

``parse1``
    The simplest form of parsing function receives a stream of input
    data, along with an optional view into the stream to limit the
    region to parse if desired. ``parse``` will internally instantiate
    an instance of the unit's ``struct``, and then feed the unit's
    parser with the data stream. However, it won't provide access to
    what's being parsed as it doesn't pass back the ``struct``.

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

Let's start by using ``parse1()``:

.. literalinclude:: examples/my-http-host-parse1.cc
   :caption: my-http-host.cc
   :lines: 10-36
   :language: c++

This code first instantiates a stream from data giving on the command
line. It freezes the stream to indicate that no further data will
arrive later. Then it sends the stream into the ``parse1()`` function
for processing.

We can now use the standard C++ compiler to build all this into an
executable, leveraging ``spicy-config`` to add the necessary flags
for finding includes and libraries::

    # clang++ -o my-http my-http-host.cc my-http.cc my-http-linker.cc $(spicy-config --cxxflags --ldflags)
    # ./my-http $'GET index.html HTTP/1.0\n'
    GET, /index.html, 1.0

The output comes from the execution of the ``print`` statement inside
the Spicy grammar, demonstrating that the parsing proceeded as
expected.

When using ``parse1()`` we don't get access to the parsed information.
If we want that, we can use ``parse2()`` instead and provide it with a
``struct`` to fill in:

.. literalinclude:: examples/my-http-host-parse2.cc
   :caption: my-http-host.cc
   :lines: 10-45
   :emphasize-lines: 19-28
   :language: c++

::

    # clang++ -o my-http my-http-host.cc my-http-host.cc $(spicy-config --cxxflags --ldflags)
    # ./my-http $'GET index.html HTTP/1.0\n'
    GET, /index.html, 1.0
    method : GET
    uri    : /index.html
    version: 1.0

Another approach to retrieving field values goes through Spicy hooks
calling back into the host application. That's how the Zeek's Spicy support
operates. Let's say we want to execute a custom C++ function every
time a ``RequestList`` has been parsed. By adding the following code
to ``my-http.spicy``, we (1) declare that function on the Spicy-side,
and (2) implement a Spicy hook that calls it:

.. literalinclude:: examples/my-http-host-callback.cc
   :caption: my-http.spicy
   :start-after: doc-start-callback-spicy
   :end-before: doc-end-callback-spicy
   :language: spicy

The ``&cxxname`` attribute for ``got_request_line`` indicates to Spicy
that this is a function implemented externally inside custom C++ code,
accessible through the given name. Now we need to implement that
function:

.. literalinclude:: examples/my-http-host-callback.cc
   :caption: my-http-callback.cc
   :start-after: doc-start-callback-cc
   :end-before: doc-end-callback-cc
   :language: c++

Finally, we compile it altogether:

::

    # spicyc -c -g my-http.spicy -o my-http.cc
    # spicyc -l -g my-http.cc -o my-http-linker.cc
    # spicyc -P -g my-http.spicy -o my-http.h
    # clang++ -o my-http my-http.cc my-http-linker.cc my-http-callback.cc my-http-host.cc $(spicy-config --cxxflags --ldflags)
    # ./my-http $'GET index.html HTTP/1.0\n'
    In C++ land: GET, index.html, 1.0
    GET, index.html, 1.0

Note that the C++ function signature needs to match what Spicy
expects, based on the Spicy-side prototype. If you are unsure how
Spicy arguments translate into C++ arguments, look at the C++
prototype that's included for the callback function in the output of
``-P``.

A couple more notes on the compilation process for integrating
Spicy-generated code into custom host applications:

    - Above we used ``spicyc -l`` to link our Spicy code from just a
      single Spicy source file. If you have more than one source file,
      you need to link them altogether in a single step. For example,
      if we had ``A.spicy``, ``B.spicy`` and ``C.spicy``, we'd do::

        # spicyc -c -g A.spicy -o A.cc
        # spicyc -c -g B.spicy -o B.cc
        # spicyc -c -g C.spicy -o C.cc
        # spicyc -l -g A.cc B.cc C.cc -o linker.cc
        # clang++ A.cc B.cc C.cc linker.cc -o a.out ...

    - If your Spicy code is importing any library modules (e.g., the
      standard ``filter`` module), you'll need to compile those as
      well in the same fashion.


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
process. Continuing to use the ``my-http.spicy`` example, this code
prints out our one available parser:

.. literalinclude:: examples/my-http-host-driver.cc
   :caption: my-http-host.cc
   :lines:   9-12,31-42,57-64
   :language: c++

::

    # clang++ -o my-http my-http-host.cc my-http.cc my-http-linker.cc $(spicy-config --cxxflags --ldflags)
    # ./my-http
    Available parsers:

        MyHTTP::RequestLine

Using the name of the parser (``MyHTTP::RequestLine``) we can
instantiate it from C++, and then feed it data:

.. literalinclude:: examples/my-http-host-driver.cc
   :lines:   44-53
   :language: c++

::

    # clang++ -o my-http my-http-host.cc my-http.cc my-http-linker.cc $(spicy-config --cxxflags --ldflags)
    # ./my-http $'GET index.html HTTP/1.0\n'
    GET, /index.html, 1.0

That's the output of the ``print`` statement once more.

``unit`` is of type ``spicy::rt::ParsedUnit``, which is a type-erased
class holding, in this case, an instance of
``_hlt::MyHTTP::RequestLine``. Internally, that instance went through
the ``parse3()`` function that we have encountered in the previous
section. To access the parsed fields, there's a visitor API to iterate
generically over HILTI types like this unit:

.. literalinclude:: examples/my-http-host-driver.cc
   :lines: 15-30
   :language: c++

Adding ``print(unit->value()`` after the call to ``processInput()``
then gives us this output:

::

    # clang++ -o my-http my-http-host.cc my-http.cc my-http-linker.cc $(spicy-config --cxxflags --ldflags)
    # ./my-http $'GET index.html HTTP/1.0\n'
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

.. literalinclude:: examples/my-http-host-driver-hlto.cc
    :caption: my-driver
    :lines: 31-70
    :emphasize-lines: 5-8
    :language: c++

::

    # $(spicy-config --cxx) -o my-driver my-driver.cc $(spicy-config --cxxflags --ldflags --dynamic-loading)
    # spicyc -j my-http.spicy >my-http.hlto
    # ./my-driver my-http.hlto "$(cat data)"
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
