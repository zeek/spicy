
.. _testing:

Testing
=======

Spicy's testing & CI setup includes several pieces that we discuss in
the following.

TLDR; If you make changes, make sure that ``make check`` runs through.
You need the right ``clang-format`` (see :ref:`clang_format`) and
``clang-tidy`` (see :ref:`clang_tidy`) versions for that (from Clang
>=10). If you don't have them (or want to save time), run at least
``make test``. If that still takes too long for you, run ``make
test-core``.

BTest
-----

Most tests are end-to-end tests that work from Spicy (or HILTI) source
code and check that everything compiles and produces the expected
output. We use `BTest <https://github.com/zeek/btest>`_ to drive
these, very similar to Zeek. ``make test`` from the top-level
directory will execute these tests. You get the same effect by
changing into ``tests/`` and running ``btest -j`` there (``-j``
parallelizes test execution).

The most important BTest options are:

    * ``-d`` prints debugging output for failing tests to the console

    * ``-f diag.log`` records the same debugging output into ``diag.log``

    * ``-u`` updates baselines when output changes in expected ways
      (don't forget to commit the updates)

There are some alternatives to running just all tests, per the
following:

.. rubric:: Running tests using installation after ``make install``

By default, btests are running completely out of the source & build
directories. If you run ``btest -a installation``, BTest will instead
switch to pulling everything from their installation locations. If you
have already deleted the build directory, you also need to have the
environment variable ``SPICY_INSTALLATION_DIRECTORY`` point to your
installation prefix, as otherwise BTest has no way of knowing where to
find Spicy.

Unit tests
----------

There's a growing set of units test. These are
using ``doctest`` and are executed through ``btest`` as well, so just
running tests per above will have these included.

Alternatively, the test binaries in the build directory can be executed to
exercise the tests, or one can use the ``check`` build target to execute all
unit tests.

Sanitizers
----------

To build tools and libraries with support for Clang's address/leak
sanitizer, configure with ``--enable-sanitizer``. If Clang's ``asan``
libraries aren't in a standard runtime library path, you'll also need
to set ``LD_LIBRARY_PATH`` (Linux) or ``DYLD_LIBRARY_PATH`` (macOS) to
point there (e.g., ``LD_LIBRARY_PATH=/opt/clang9/lib/clang/9.0.1/lib/linux``).

When using the Spicy plugin for Zeek and Zeek hasn't been compiled
with sanitizer support, you'll also need to set ``LD_PRELOAD`` (Linux)
or ``DYLD_INSERT_LIBRARIES`` (macOS) to the shared ``asan`` library to
use (e.g.,
``LD_PRELOAD=/data/clang9/lib/clang/9.0.1/lib/linux/libclang_rt.asan-x86_64.so``).
Because you probably don't want to set that permanently, the test
suite pays attention to a variable ``ZEEK_LD_PRELOAD``: If you set
that before running ``btest`` to the path you want in ``LD_PRELOAD``,
the relevant tests will copy the value for running Zeek.

To make the sanitizer symbolize its output you need to set the
``ASAN_SYMBOLIZER_PATH`` environment variable to point to the
``llvm-symbolizer`` binary, or make sure ``llvm-symbolizer`` is in
your ``PATH``.

.. note::

    As we are running one of the CI build with sanitizers, it's ok not
    to run this locally on a regular basis during development.

Code Quality
------------

Our CI runs the :ref:`clang_format` and :ref:`clang_tidy` checks, and
will fail if any of that doesn't pass. To execute these locally, run
the make target ``format`` and ``tidy``, respectively. Don't forget to
set ``CLANG_FORMAT`` and ``CLANG_TIDY`` to the right version of the
binary if they aren't in your ``PATH``.


CI also runs `pre-commit <https://pre-commit.com>`_ with a
configuration pre-configured in `.pre-commit-config.yaml`. To run that
locally on every commit, install pre-commit and then put its git hook
in place through executing ``pre-commit install``; see the
`installation instructions <https://pre-commit.com/#install>`_ for
more details.

Docker Builds
-------------

We are shipping a number of Docker files in ``docker/``; see
:ref:`docker` for more information. As part of our CI, we make sure
these build OK and pass ``btest -a installation``. If you have Docker
available, you can run these individually yourself through ``make
test-<platform>`` in ``docker/``. However, usually it's fine to leave
this to CI.


How Test Your Branch
--------------------

If you run ``make check`` in the top-level directory you get the
combination of all the btests, formatting, and linting. That's the
best check to do to make sure your branch is in good shape, in
particular before filing a pull request.
