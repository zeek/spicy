
.. _dev_architecture:

Architecture
============

Components & Data Flow
----------------------

.. image:: /_static/architecture.svg

Runtime Libraries
-----------------

HILTI and Spicy each come with their own runtime libraries providing
functionality that the execution of compiled code requires. The bulk
of the functionality here resides with the HILTI side, with the Spicy
runtime adding pieces that are specific to its use case (i.e.,
parsing).

Conceptually, there are a few different categories of functionality
going into these runtime libraries, per the following summary.

.. rubric:: Categories of Functionality

.. image:: /_static/runtime-libraries.svg

Category 1
    Public library functionality that Spicy programs can ``import``
    (e.g., functions like ``spicy::current_time()`` inside the
    ``spicy`` module; filters like ``filter::Zlib`` inside the
    ``filter`` module). This functionality is declared in
    ``spicy/lib/*.spicy`` and implemented in C++ in ``libspicy-rt.a``.

Category 2
    Public library functionality that HILTI programs can ``import``
    (e.g., the ``hilti::print()`` function inside the ``hilti``
    module). This functionality is declared in ``hilti/lib/hilti.hlt``
    and implemented in C++ in ``libhilti-rt.a``.

    .. note::

        "Public functionality" here means being available to any
        *HILTI* program. This functionality is *not* exposed inside
        Spicy, and hence usually not visible to users unless they
        happen to start writing HILTI programs (e.g., when adding test
        cases to the code base).

Category 3
    Public library functionality for C++ host applications to
    ``#include`` for interacting with the generated C++ code (e.g., to
    retrieve the list of available Spicy parsers, start parsing, and
    gain access to parsed values). This is declared inside the
    ``hilti:rt`` C++ namespace by ``hilti/include/rt/libhilti.h``
    for HILTI-side functionality; and inside the ``spicy::rt``
    namespace by ``spicy/include/rt/libspicy.h`` for purely Spicy-side
    functionality. This functionality is implemented in
    ``libhilti-rt.a`` and ``libspicy-rt.a``, respectively.

    .. note::

        Everything in the sub-namespaces ``{hilti,spicy}::rt::detail``
        remains private and is covered by categories 4 and 5.

Category 4
    Private Spicy-side library functionality that the HILTI code
    coming out of Spicy compilation can ``import`` (e.g., functions to
    access parsing input, such as ``spicy_rt::waitForInput()``;
    HILTI-side type definitions for Spicy-specific types, such as for
    a ``sink``). This functionality is declared in
    ``spicy/lib/spicy_rt.spicy`` and implemented in C++ in
    ``libspicy-rt.a``.

Category 5
    Private HILTI-side library functionality for use by C++ code
    generated from HILTI code. This is declared by
    ``hilti/include/rt/libhilti.h`` inside the ``hilti::rt::detail``
    namespace. The functionality is implemented in ``libhilti-rt.a``.
    (The generated C++ code uses public ``hilti::rt`` functionality
    from Category 3 as well.)

    .. note::

        This category does not have any Spicy-side logic (by
        definition, because Spicy does not generate C++ code
        directly). Everything in ``libspicy-rt.a``, and
        ``spicy::rt::detail`` is covered by one of the other
        categories.

.. rubric:: What goes where?

Think of Category 1 as the "Spicy standard library": functionality for
user-side Spicy code to leverage.

Category 2 is the same for HILTI, except that the universe of HILTI
users remains extremely small right now (it’s just Spicy and people
writing tests).

Category 3 is our client-side C++ API for host applications to drive
Spicy parsers and retrieve results.

When adding new functionality, one needs to decide between the HILTI
and Spicy sides. Rules of thumb:

    1. If it’s "standard library"-type stuff that's meant for Spicy
       users to ``import``, make it part of Category 1.

    2. If it’s something that’s specific to parsing, add it to the
       Spicy side, either Category 3 for public functionality meant to
       be used by host applications; or Category 4 if it’s something
       needed just by the generated HILTI code doing the parsing.

    3. If it's something that’s generic enough to be used by other
       HILTI applications (once we get them), add it to the HILTI
       side, either Category 2 or 5. Think, e.g., a Zeek script
       compiler.
