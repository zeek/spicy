
.. _installation:

Installation
=============

Spicy can be installed from pre-built binaries (Linux, macOS) or with
Homebrew (macOS), executed via Docker containers (Linux), or built
from source (Linux, macOS, FreeBSD):

.. contents::
    :local:

We generally aim to follow `Zeek's platform policy
<https://github.com/zeek/zeek/wiki/Platform-Support-Policy>`_ on which
platforms to support and test.

.. note::

    If your goal is to use Spicy with Zeek, you can skip these
    installation instructions. Zeek comes with Spicy support built-in
    by default since version 5.0. See the :zeek:`Zeek documentation
    <devel/spicy/installation.html>` for more.

Pre-built binaries
------------------

.. _prebuilt_linux:

Linux
~~~~~

We provide pre-built Spicy binaries for a range of Linux
distributions, both for the current release version and for
development builds made from the Git ``main`` branch.

These binary artifacts are distributed as either DEB or RPM packages
for the corresponding distribution; or, in a couple cases, as TAR
archives. To install the binaries, download the corresponding package
and execute one of the following:

DEB packages
    .. code::

        # dpkg --install spicy.deb

RPM packages
    .. code::

        # rpm -i spicy.rpm

TAR archives
    The TAR archives need to be unpacked into ``/opt/spicy``. Any
    previous installation must be removed first::

        # rm -rf /opt/spicy && mkdir /opt/spicy
        # tar xf spicy.tar.gz -C /opt/spicy --strip-components=1

.. _dockerfiles:

The binaries may require installation of additional dependencies; see
the ``Dockerfile`` for the respective platform for what's needed.

.. list-table::
    :widths: auto
    :header-rows: 1
    :align: center

    * - Platform
      - Release Version
      - Development Version
      - Dockerfile

    * - Alpine 3.18
      - :package-release-tgz:`TAR <linux_alpine_3_18>`
      - :package-dev-tgz:`TAR <docker_alpine_3_18>`
      - :repo:`Dockerfile <docker/Dockerfile.alpine-3.18>`

    * - CentOS Stream 9
      - :package-release-rpm:`TAR <linux_centos_stream_9>`
      - :package-dev-rpm:`RPM <docker_centos_stream_9>`
      - :repo:`Dockerfile <docker/Dockerfile.centos-stream-9>`

    * - Debian 12
      - :package-release-deb:`DEB <linux_debian12>`
      - :package-dev-deb:`DEB <docker_debian12>`
      - :repo:`Dockerfile <docker/Dockerfile.debian-12>`

    * - Fedora 41
      - :package-release-rpm:`RPM <linux_fedora41>`
      - :package-dev-rpm:`RPM <docker_fedora41>`
      - :repo:`Dockerfile <docker/Dockerfile.fedora-41>`

    * - Fedora 42
      - :package-release-rpm:`RPM <linux_fedora42>`
      - :package-dev-rpm:`RPM <docker_fedora42>`
      - :repo:`Dockerfile <docker/Dockerfile.fedora-42>`

    * - Ubuntu 22
      - :package-release-deb:`DEB <linux_ubuntu22>`
      - :package-dev-deb:`DEB <docker_ubuntu22>`
      - :repo:`Dockerfile <docker/Dockerfile.ubuntu-22>`

    * - Ubuntu 24
      - :package-release-deb:`DEB <linux_ubuntu24>`
      - :package-dev-deb:`DEB <docker_ubuntu24>`
      - :repo:`Dockerfile <docker/Dockerfile.ubuntu-24>`

macOS
~~~~~

.. _homebrew_macos:

Homebrew
^^^^^^^^

We provide a Homebrew formula for installation of Spicy. After
`installing Homebrew <https://docs.brew.sh/Installation>`_ add the
Zeek tap::

    # brew tap zeek/zeek

To install the most recent Spicy release version, execute::

    # brew install spicy

To instead install the current development version, execute::

    # brew install --HEAD spicy

.. _prebuilt_macos:

Pre-built binaries
^^^^^^^^^^^^^^^^^^

We provide TAR archives with pre-built binaries for the following
macOS versions:

.. list-table::
    :widths: auto
    :header-rows: 1
    :align: center

    * - macOS
      - Release Version
      - Development Version

    * - Monterey (12)
      -
      - :package-dev-tgz:`TAR <macos_monterey>`

    * - Ventura (13)
      -
      - :package-dev-tgz:`TAR <macos_venture>`

The TAR archives need to be unpacked into ``/opt/spicy``. Any previous
installation must be removed first. To prevent macOS from quarantining
the files, you should download and unpack via the command line::

    # curl -L <link-per-above> -o spicy.tar.gz
    # rm -rf /opt/spicy && mkdir /opt/spicy
    # tar xf spicy.tar.gz -C /opt/spicy --strip-components 1

For JIT support, these binaries require an Xcode installation.

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

        * `Python <https://www.python.org/downloads/>`_ >= 3.4
        * `Sphinx <https://www.sphinx-doc.org/en/master>`_  >= 1.8
        * `Pygments <https://pygments.org/>`_  >= 2.5
        * `Read the Docs Sphinx Theme <https://sphinx-rtd-theme.readthedocs.io/en/stable/>`_  (``pip install sphinx_rtd_theme``)

In the following we record how to get these dependencies in place on
some popular platforms. Please :issue:`file an issue <>` if you have
instructions for platforms not yet listed here.

Linux
^^^^^

See the corresponding :ref:`Dockerfiles <dockerfiles>`.

macOS
^^^^^

Make sure you have Xcode installed, including its command-line tools
(``xcode-select --install``).

If you are using `Homebrew <https://brew.sh>`_::

    # brew install bison flex cmake ninja python@3.8 sphinx-doc
    # pip3 install btest

If you are using `MacPorts <https://www.macports.org>`_::

    # port install flex bison cmake ninja python38 py38-pip
    # pip install btest

If you want to build the documentation as well, also install
``sphinx_rtd_theme`` and ``diagrams`` through *pip*.

FreeBSD
^^^^^^^

See the :repo:`prepare script <ci/prepare_freebsd.sh>` coming with
the Spicy distribution.

Building Spicy
~~~~~~~~~~~~~~

Get the code::

    # git clone --recursive https://github.com/zeek/spicy

The short version to build Spicy is the usual process then::

    # ./configure && make && make install

However, you may want to customize the build a bit, see the output
``./configure --help`` for the available options. In particular, you
can use ``--prefix=/other/path`` to install into something else than
``/usr/local``.

The final ``configure`` output will summarize your build's
configuration.

.. note::

    For developers, the following ``configure`` options may be
    particular useful:

        - ``--enable-ccache``: use the ``ccache`` compiler cache to speed up compilation
        - ``--enable-debug``: compile a non-optimized debug version
        - ``--enable-sanitizer``: enable address & leak sanitizers
        - ``--generator=Ninja``: use the faster ``ninja`` build system instead of ``make``

    Using Ninja and ``ccache`` will speed up compile times. On Linux,
    compiling will also be quite a bit faster if you have the "Gold
    linker" available. To check if you do, see if ``which ld.gold``
    returns anything. If yes, ``configure`` will automatically pick it
    up.

Once you have configured Spicy, running ``make`` will change into the
newly created ``build`` directory and start the compilation there.
Once finished, ``make test`` will execute the test suite. It will take
a bit, but all tests should be passing (unless explicitly reported as
expected to fail). Finally, ``make install`` will install Spicy
system-wide into the configured prefix. If you are installing into a
non-standard location, make sure that ``<prefix>/bin`` is in your
``PATH``.

.. note:: You can also use the Spicy tools directly out of the build
   directory without installing; the binaries land in ``build/bin``.

To build Spicy's documentation, run ``make`` inside the ``docs/`` directory.
Documentation will then be located in ``build/doc/html``.

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
