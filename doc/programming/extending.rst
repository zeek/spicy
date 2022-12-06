
.. _extending:

=================
Custom Extensions
=================

As shown in the :ref:`library section <library_functions>`, Spicy's
runtime library comes with a set of built-in functions that grammars
can leverage for more complex tasks, such as Base64 decoding and
``zlib`` decompression. Behind the scenes, these functions are just
small Spicy wrappers that call into corresponding C++ code. This
section describes how you can provide your own built-in functions
leveraging custom external C++ code.

Basic Example
=============

Let's start with a simple example. Say we want to make a ``rot13``
function available to Spicy that rotates each letter of a string by 13
characters, using the following C++ implementation:

.. literalinclude:: examples/mylibrary.cc
   :caption: mylibrary.cc
   :language: c++

We can make this function available to Spicy by declaring it inside a
custom module like this:

.. literalinclude:: examples/mylibrary.spicy
   :caption: mylibrary.spicy
   :language: spicy

Now we can use it in our Spicy code:

.. spicy-code:: rot13.spicy

    module Example;

    import MyLibrary;

    const data = "Hello, world!";
    global encrypted = MyLibrary::rot13(data);
    global decrypted = MyLibrary::rot13(encrypted);

    print "'%s' -> '%s' -> '%s'" % (data, encrypted, decrypted);

To compile and execute this, we give ``spicyc`` all three files:

.. spicy-output:: rot13.spicy
    :exec: spicyc -j %INPUT programming/examples/mylibrary.spicy programming/examples/mylibrary.cc
    :show-as: spicyc -j %INPUT mylibrary.spicy mylibrary.cc

Let's look more closely at what's going on here.

In ``mylibrary.spicy``, the function attribute ``&cxxname`` is the
marker for Spicy that we're not declaring a standard Spicy function
but an external function that's implemented in C++. The value of that
attribute is the C++-side name of the function, which Spicy will use
to call it. In our case, the C++ name is the same as the fully
qualified Spicy-side name, because we aligned C++ namespace and
function ID accordingly. However, that doesn't need to be the case;
see below for more.

Besides the naming, the key to interfacing Spicy with C++ lies in
aligning the types for function parameters and results between the two
sides. Internally, Spicy automatically creates a C++ function
prototype for any function declaration coming with a ``&cxxname``
attribute. To do so, Spicy maps its own types to corresponding C++
types. We can see how that looks in  our example by running ``spicyc
-gP`` to print out the generated function prototype (plus a bit of
boilerplate to produce a complete C++ ``#include`` header):

.. spicy-output:: mylibrary.spicy
    :exec: spicyc -gP programming/examples/mylibrary.spicy
    :show-as: spicyc -gP mylibrary.spicy

As you can see, Spicy maps ``rot13``'s string argument and result into
``std::string``, which happens to be exactly what we need in our
simple example.

.. todo::

    We should tweak ``-P`` so that it disables optimization
    automatically (because that just removes the supposedly unused
    function). (:issue:`1284`)

Advanced Usage
==============

In practice, it's often not quite as simple to provide new built-in
functions as in our example because parameters or results might not
directly align between Spicy and C++. In the following we walk through
aspects that typically come up here, in particular when interfacing to
already existing C++ code that doesn't know anything about Spicy.

Function naming
^^^^^^^^^^^^^^^

As said above, the name of the C++ function must be provided to Spicy
through the ``&cxxname`` attribute. The name may be namespaced, but
can also just be a global identifier, depending on what the C++ code
expects. Spicy will simply use the name literally in any C++ code it
generates.

Type mapping
^^^^^^^^^^^^

For each Spicy type, the compiler picks a corresponding C++ type when
generating an internal function prototype. The following table shows
those mappings:

.. list-table::
    :widths: auto
    :header-rows: 1
    :align: center

    * - Spicy Type
      - C++ type

    * - ``addr``
      - ``hilti::rt::Address``

    * - ``bitfield(N)``
      - ``uintN_t``

    * - ``bool``
      - ``hilti::rt::Bool``

    * - ``bytes``
      - ``hilti::rt::Bytes``

    * - ``enum``
      - ``enum`` (a corresponding C++ enum type will be generated)

    * - ``exception``
      - ``hilti::rt::Exception``

    * - ``(u)int8/16/32/64``
      - ``(u)int_8/16/32/64_t``

    * - ``interval``
      - ``hilti::rt::Interval``

    * - ``list<T>``
      - ``hilti::rt::Vector<T>``

    * - ``map<K,V>``
      - ``hilti::rt::Map<K,V>``

    * - ``optional<T>``
      - ``std::optional<T>``

    * - ``port``
      - ``hilti::rt::Port``

    * - ``real``
      - ``double``

    * - ``regexp``
      - ``hilti::rt::RegExp``

    * - ``set<T>``
      - ``hilti::rt::Set<T>``

    * - ``sink``
      - ``spicy::rt::Sink``

    * - ``stream``
      - ``spicy::rt::Stream``

    * - ``string``
      - ``std::string``

    * - ``struct``
      - ``struct`` (a corresponding C++ struct type will be generated)

    * - ``time``
      - ``hilti::rt::Time``

    * - ``tuple<Ts>``
      - ``std::tuple<Ts>``

    * - ``unit``
      - ``struct`` (a corresponding C++ struct type will be generated)

    * - ``vector<T>``
      - ``hilti::rt::Vector<T>``

The C++ types that reside inside the ``hilti::rt`` or ``spicy::rt``
scopes, are defined in ``hilti/runtime/libhilti.h`` and
``spicy/runtime/libspicy.h``, respectively.

If these type mappings match what your C++ code expects---as it did in
our example---then there's nothing else to do. If they don't, you have
three options:

1. You adapt the function's C++ declaration accordingly, assuming you
   can modify it.

2. If you are lucky, you may be able to get away with "slightly
   mismatching" C++ types as long as (a) they coerce into each other,
   and (b) Spicy is able to see the original prototype so that it can
   skip generating its own. However, it may be tricky to satisfy these
   two conditions, see the box below for more.

3. You provide an additional C++ wrapper function receiving the
   expected types and forwarding them to the actual function as
   appropriate.

.. admonition:: Using external prototypes

   Per option (2) above, it is possible to get away with "slightly
   mismatching" types in some cases. For example, if your C++ function
   expects just an ``unsigned int`` for one of its arguments, but
   Spicy passes a value as an ``uint8_t``, that will compile just
   fine. But there's a caveat: to make that work, you need to prevent
   Spicy from generating its own prototype for the function, as the
   two would mismatch. There's a ``&have_prototype`` attribute for
   that: If you add that to the Spicy-side function declaration, Spicy
   will assume that it can rely on an already existing C++ prototype
   instead of creating its own.

   However, there's a second challenge here now: Spicy's generated C++
   code needs to actually find that existing prototype somewhere—-but
   unfortunately, there's currently no way of explicitly providing
   it. The only case where you can make this work right now is when
   Spicy's C++ runtime library happens to be already including a C++
   header that comes with your desired prototype. That's unlikely for
   any non-standard functionality, but it may work if you're wrapping
   a standard system function, such as anything from ``stdlib.h`` for
   example (e.g., ``random()``).

   .. todo::

      We should add a mechanism to provide an arbitrary
      custom C++ prototype directly. (:issue:`1286`)

   There's a similar trick for complex types, such as structs and
   enums: If your C++ function requires a type that Spicy doesn't
   know anything about, you can declare a Spicy-side dummy
   substitute like this:

   .. spicy-code::

       public type MyType = __library_type("MyType");

   Then you can use ``MyType`` as as type in Spicy-side declarations.
   The name given to ``__library_type`` works similar to function
   names provided to ``&cxxname``: the Spicy compiler will take them
   literally to refer to the C++ type. However, this will work only in
   similar situations as ``&have_prototype```: the compiler must be
   able to find an existing declaration for that C++ type in any of
   its standard includes files. It's fine for that declaration to be
   just a forward declaration if that's sufficient for the C++ code to
   compile).

Linking to Libraries
^^^^^^^^^^^^^^^^^^^^

In our example, we gave the custom C++ code directly to the Spicy
compiler. That code will then simply be compiled along with everything
else and be linked into the resulting binary code. Often, however, you
may instead want to make functions available to Spicy that are
implemented inside an external C++ library. In that case, Spicy will
need to link the binary code to that library. To support that,
``spicyc`` provides an option ``--cxx-link`` that takes the full path
to a (static or shared) library to link in. For example::

  # spicyc -j --cxx-link /usr/local/lib/libz.a mycode.spicy

``--cxx-link`` can be specified multiple times.

Include paths
^^^^^^^^^^^^^

If your C++ code requires additional include files outside of standard
include paths, you can set the environment variable
``HILTI_CXX_INCLUDE_DIRS`` to a colon-separated list of additional
directories for ``spicyc`` to use when compiling C++ code.
