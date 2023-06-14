
|today|.

================================================================
Spicy --- Generating Robust Parsers for Protocols & File Formats
================================================================

.. literalinclude:: examples/frontpage.spicy
    :language: spicy

::

    # echo "GET /index.html HTTP/1.0" | spicy-driver http-request.spicy
    [$method=b"GET", $uri=b"/index.html", $version=[$number=b"1.0"]]

Overview
    Spicy is a parser generator that makes it easy to create robust
    C++ parsers for network protocols, file formats, and more. Spicy
    is a bit like a "yacc for protocols", but it's much more than
    that: It's an all-in-one system enabling developers to write
    attributed grammars that describe both syntax and semantics of an
    input format using a single, unified language. Think of Spicy as a
    domain-specific scripting language for all your parsing needs.

    The Spicy toolchain turns such grammars into efficient C++ parsing
    code that exposes an API to host applications for instantiating
    parsers, feeding them input, and retrieving their results. At
    runtime, parsing proceeds fully incrementally—and potentially
    highly concurrently—on input streams of arbitrary size.
    Compilation of Spicy parsers takes place either just-in-time at
    startup (through a C++ compiler); or ahead-of-time either by
    creating pre-compiled shared libraries, or by giving you generated
    C++ code that you can link into your application.

    Spicy comes with Zeek support that enables adding new protocol and
    file analyzers to `Zeek <https://www.zeek.org>`_ without having to
    write any C++ code. You define the grammar, specify which Zeek
    events to generate, and Spicy takes care of the rest. There's also
    a `Zeek analyzers <https://github.com/zeek/spicy-analyzers>`_
    package that provides Zeek with several new, Spicy-based
    analyzers.

    See our :ref:`collection of example grammars <examples>` to get a
    sense of what Spicy looks like.

License
    Spicy is open source and released under a BSD license, which
    allows for pretty much unrestricted use as long as you leave the
    license header in place. You fully own any parsers that Spicy
    generates from your grammars.

History
    Spicy was originally developed as a research prototype at the
    `International Computer Science Institute
    <http://www.icsi.berkeley.edu/>`_ with funding from the `U.S.
    National Science Foundation <https://www.nsf.gov>`_. Since then,
    Spicy has been rebuilt from the ground up by `Corelight
    <https://www.corelight.com>`_, which has contributed the new
    implementation to the Zeek Project.


Getting in Touch
----------------

Having trouble using Spicy? Have ideas how to make Spicy better? We'd
like to hear from you!

    - Report issues on the GitHub `ticket tracker <https://github.com/zeek/spicy/issues>`_.

    - Ask the ``#spicy`` channel on `Zeek's Slack <https://zeek.org/connect>`_.

    - Propose ideas, and show what you're doing, on GitHub's `Discussions <https://github.com/zeek/spicy/discussions>`_.

    - Visit the [Zeek community](https://community.zeek.org) to discuss Spicy under
      the [Spicy tag](https://community.zeek.org/c/spicy/).

    - To follow development, subscribe to the `commits mailing list
      <https://groups.google.com/a/zeek.org/g/spicy-commits/>`_ (it can be
      noisy!).

Documentation
-------------

.. toctree::
   :maxdepth: 2
   :numbered:

   installation
   getting-started
   faq
   tutorial/index
   programming/index
   toolchain
   zeek
   host-applications
   release-notes
   development/index

Index
-----

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
