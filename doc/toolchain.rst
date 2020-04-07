
.. _toolchain:

=========
Toolchain
=========

.. _spicy-build:

``spicy-build``
===============

``spicy-build`` is a shell frontend that compiles Spicy source code
into a standalone executable by running :ref:`spicyc` to generate the
necessary C++ code, then spawning the system compiler to compile and
link that.

.. spicy-output:: usage-spicy-build
    :exec: spicy-build -h

.. _spicy-config:

``spicy-config``
================

``spicy-config`` reports information about Spicy's build &
installation options.

.. spicy-output:: usage-spicy-config
    :exec: spicy-config -h

.. _spicyc:

``spicyc``
==========

``spicyc`` compiles Spicy code into C++ output, optionally also
executing it directly through JIT.

.. spicy-output:: usage-spicyc
    :exec: spicyc -h

.. _spicy-driver:

``spicy-driver``
================

``spicy-driver`` is a standalone Spicy host application that compiles
& executes Spicy parsers on the fly, and then feeds them data for
parsing from standard input.

.. spicy-output:: usage-spicy-driver
    :exec: spicy-driver -h
