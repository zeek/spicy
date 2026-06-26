
.. _installation:

Installation
=============

Spicy can be installed from source (Linux, macOS) or with
Homebrew (macOS), and executed via Docker containers.

.. contents::
    :local:

We generally aim to follow `Zeek's platform policy
<https://github.com/zeek/zeek/wiki/Platform-Support-Policy>`_ on which
platforms to support and test.

.. note::

    If your goal is to use Spicy with Zeek, you can skip these
    installation instructions. Zeek comes with Spicy support built-in
    by default since version 5.0. See the :zeek:`Zeek documentation
    <install.html>` for more.

.. _building_from_source:

Building from source
--------------------

Prerequisites
~~~~~~~~~~~~~

To build Spicy from source, you will need:

    - For compiling the toolchain:

        * A C++ compiler that supports C++20 (known to work are Clang >= 9 and GCC >= 12)
        * `CMake <https://cmake.org>`_  >= 3.15
        * `Bison <https://www.gnu.org/software/bison>`_  >= 3.0
        * `Flex <https://www.gnu.org/software/flex>`_  >= 2.6
        * `Zlib <https://www.zlib.net>`_ (no particular version)

    - For testing:

        * `Python <https://www.python.org/downloads/>`_ >= 3.4
        * `BTest <https://github.com/zeek/btest>`_  >= 0.66 (``pip install btest``)
        * Bash (for BTest)

    - For building the documentation:

        * `Python <https://www.python.org/downloads/>`_ >= 3.10
        * the Python packages requirements listed in :repo:`the doc/ folder <doc/requirements.txt>`.

In the following we record how to get these dependencies in place on
some popular platforms.

Linux
^^^^^

See the corresponding :repo:`Dockerfiles <docker/>`.

macOS
^^^^^

Make sure you have Xcode installed, including its command-line tools
(``xcode-select --install``).

If you are using `Homebrew <https://brew.sh>`_::

    # brew install bison flex cmake ninja python@3.8 sphinx-doc
    # pip3 install btest

If you are using `MacPorts <https://www.macports.org>`_::

    # port install flex bison cmake ninja python310 py310-pip
    # pip install btest

If you want to build the documentation as well, also install
``sphinx_rtd_theme`` and ``diagrams`` through ``pip``.

Building
~~~~~~~~

We provide a ``./configure`` script to set up and parameterize the build and to
produce e.g., a ``Makefile``. See ``./configure --help`` for the available
options. The general workflow is::

    # ./configure
    # make -C build
    # make -C build install

See our :repo_main:`CI setup <.github/workflows/check.yml>` for typical
configurations.

Homebrew (macOS)
----------------

We provide a Homebrew formula for installation of Spicy. After
`installing Homebrew <https://docs.brew.sh/Installation>`_ add the
Zeek tap::

    # brew tap zeek/zeek

To install the most recent Spicy release version, execute::

    # brew install spicy

To instead install the current development version, execute::

    # brew install --HEAD spicy

.. _docker:

Using Docker
------------

The Zeek Docker images include Spicy. See their `documentation
<https://docs.zeek.org/en/master/install.html#docker-images>`__ on how to
run them.

.. note::

    Docker Desktop for Mac uses a VM behind the scenes to host the
    Docker runtime environment. By default it allocates 2 GB of RAM to
    the VM. This is not enough to compile Spicy analzers and will cause
    an error that looks something like this::

        c++: internal compiler error: Killed (program cc1plus)
        Please submit a full bug report,
        with preprocessed source if appropriate.
        See <file:///usr/share/doc/gcc-7/README.Bugs> for instructions.

    This is due to the VM hitting an out-of-memory condition. To avoid
    this you will need to allocate more RAM to the VM. Click on the Docker
    Icon in your menubar and select "Preferences". Click on the "Advanced"
    tab and then use the slider to select 8 GB of RAM. Docker Desktop will
    restart and then you will be ready to go.

.. _parser-development-setup:

Parser development setup
------------------------

In order to speed up compilation of Spicy parsers, users can create a
cache of precompiled files. This cache is tied to a specific Spicy
version, and needs to be recreated each time Spicy is updated.

To precompile the files execute the following command::

    # spicy-precompile-headers

.. note::

    By default the cache is located in the folder
    ``.cache/spicy/<VERSION>`` inside the user's home directory. This
    location can be overridden by setting the environment variable
    ``SPICY_CACHE`` to a different folder path, both when executing
    ``spicy-precompile-headers`` and Spicy toolchain commands.
