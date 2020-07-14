
|today|.

==================================================
Spicy --- Generating Parsers for Protocols & Files
==================================================

.. literalinclude:: examples/frontpage.spicy
    :language: text

Overview
    Spicy is a C++ parser generator that makes it easy to create
    robust parsers for network protocols, file formats, and more.
    Spicy is a bit like a "yacc for protocols", but it's much more
    than that: It's an all-in-one system enabling developers to write
    attributed grammars that define both syntax and semantics of an
    input format using a single, unified language. Think of Spicy as a
    domain-specific scripting language for all your parsing needs.

    The Spicy toolchain turns such grammars into efficient C++ parsing
    code that exposes an API to host applications for instantiating
    parsers, feeding them input, and retrieving their results. At
    runtime, parsing proceeds fully incrementally—and potentially
    highly concurrently—on input streams of arbitrary size.
    Compilation of Spicy parsers takes place either just-in-time at
    startup (through Clang/LLVM), or ahead-of-time either by creating
    pre-compiled shared libraries or simply by giving you C++ code that
    you can link into your application.

    Spicy comes with a `Zeek <https://www.zeek.org>`_ plugin that
    enables adding new protocols to Zeek without having to write any
    C++ code. You define the grammar, specify which Zeek events to
    generate, and Spicy takes care of the rest.

    See our growing :ref:`collection of example grammars <examples>`
    to get a sense of how Spicy works.

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

.. note::

    Spicy is currently in a very early beta phase, it's *not* yet
    ready for production usage. You'll find plenty rough edges still,
    including unstable code, missing features, and confusing error
    messages if you do something unexpected. Specifics of the language
    and the toolset may still change as well---there's no release yet,
    just a git ``master`` branch that keeps moving. We don't recommend
    Spicy and its parsers for anything critical yet, but we're very
    interested in feedback as we're working to stabilize all this.

Getting in Touch
----------------

Having trouble using Spicy? Have ideas how to make Spicy better? We'd
like to hear from you!

    - Check out the `FAQ <http://docs.zeek.org/projects/spicy>`_ to see if any of that helps.

    - Report issues on `GitHub <https://github.com/zeek/spicy/issues>`_.

    - Ask the ``#spicy`` channel on `Zeek's Slack <https://zeek.org/connect>`_.

    - Subscribe to the `Spicy mailing list <http://mailman.icsi.berkeley.edu/mailman/listinfo/spicy>`_.

    - To follow development, subscribe to the `commits mailing list
      <http://mailman.icsi.berkeley.edu/mailman/listinfo/spicy-commits>`_ (it
      can be noisy).

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
