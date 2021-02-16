
.. _installation:

Installation
=============

Spicy can be installed from pre-built binaries (:ref:`Linux <prebuilt_linux>`,
:ref:`MacOS <prebuilt_macos>`) or with :ref:`Homebrew (macOS)
<homebrew_macos>`, executed via :ref:`Docker containers <docker>`, or
:ref:`built from source <building_from_source>`.

Pre-built binaries
------------------

.. _prebuilt_linux:

Linux
~~~~~

We provide pre-built binaries for some platforms from the Git ``master``
branch. Artifacts are distributed as TAR archives which can be unpacked to any
location::

    # Unpack archive to e.g., /opt/spicy overwriting any previous installation.
    # Writing to /opt/spicy likely requires superuser priviledges.
    # The path /opt/spicy can be replaced with a custom path.
    rm -rf /opt/spicy && mkdir /opt/spicy
    tar xf spicy-linux.tar.gz -C /opt/spicy --strip-components=1

The binaries might require installation of additional dependencies;
see the ``Dockerfile`` for the respective platform.

alpine-3.12
    :download:`master <https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/docker_alpine_3_12/packages/build/spicy-linux.tar.gz>`,
    `Dockerfile <https://github.com/zeek/spicy/blob/master/docker/Dockerfile.alpine-3.12>`__

centos-7
    :download:`master <https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/docker_centos_7/packages/build/spicy-linux.tar.gz>`,
    `Dockerfile <https://github.com/zeek/spicy/blob/master/docker/Dockerfile.centos-7>`__

centos-8
    :download:`master <https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/docker_centos_8/packages/build/spicy-linux.tar.gz>`,
    `Dockerfile <https://github.com/zeek/spicy/blob/master/docker/Dockerfile.centos-8>`__

debian-9
    :download:`master <https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/docker_debian9/packages/build/spicy-linux.tar.gz>`,
    `Dockerfile <https://github.com/zeek/spicy/blob/master/docker/Dockerfile.debian-9>`__

debian-10
    :download:`master <https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/docker_debian10/packages/build/spicy-linux.tar.gz>`,
    `Dockerfile <https://github.com/zeek/spicy/blob/master/docker/Dockerfile.debian-10>`__

fedora-32
    :download:`master <https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/docker_fedora32/packages/build/spicy-linux.tar.gz>`,
    `Dockerfile <https://github.com/zeek/spicy/blob/master/docker/Dockerfile.fedora-32>`__

fedora-33
    :download:`master <https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/docker_fedora33/packages/build/spicy-linux.tar.gz>`,
    `Dockerfile <https://github.com/zeek/spicy/blob/master/docker/Dockerfile.fedora-33>`__

ubuntu-16
    :download:`master <https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/docker_ubuntu16/packages/build/spicy-linux.tar.gz>`,
    `Dockerfile <https://github.com/zeek/spicy/blob/master/docker/Dockerfile.ubuntu-16>`__

ubuntu-18
    :download:`master <https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/docker_ubuntu18/packages/build/spicy-linux.tar.gz>`,
    `Dockerfile <https://github.com/zeek/spicy/blob/master/docker/Dockerfile.ubuntu-18>`__

ubuntu-20
    :download:`master <https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/docker_ubuntu20/packages/build/spicy-linux.tar.gz>`,
    `Dockerfile <https://github.com/zeek/spicy/blob/master/docker/Dockerfile.ubuntu-20>`__

macOS
~~~~~

.. _homebrew_macos:

.. rubric:: Homebrew

We provide a Homebrew formula for installation of ``HEAD`` versions of Spicy.
After `installing Homebrew <https://docs.brew.sh/Installation>`_ add the Zeek
tap::

    brew tap zeek/zeek

To install Spicy execute::

    brew install --HEAD spicy

.. _prebuilt_macos:

.. rubric:: Pre-built binaries

We additionally provide pre-build nightly binaries for :download:`MacOS Catalina
<https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/macos_catalina/packages/build/spicy-darwin.tar.gz>`
and :download:`MacOS Big Sur
<https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/macos_big_sur/packages/build/spicy-darwin.tar.gz>`.
To prevent MacOS from quarantining the files, you should download and unpack
via the command line, e.g.::

    curl -L https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/macos_big_sur/packages/build/spicy-darwin.tar.gz -o spicy-darwin.tar.gz
    tar xf spicy-darwin.tar.gz

For JIT support these binaries require an Xcode installation.

These binaries require Zeek if you want to use the Spicy Zeek plugin::

    brew install zeek  # for Zeek integration

.. _docker:

Using Docker
------------

The Spicy distribution comes with a :repo:`set of Docker files
<docker>` that create images for selected Linux distributions. We walk
through how to use these in the following. We also welcome
contributions to support more Linux distributions. If you create a new
Docker file, please file a :pr:`pull request <>`.

Pre-requisites
~~~~~~~~~~~~~~

You first need to install Docker on your host system if you haven't yet.

.. rubric:: Linux

All major Linux distributions provide Docker. Install it using your
package manager. Alternatively, follow the official
`instructions <https://docs.docker.com/install/>`__.

.. rubric:: macOS

Install `Docker Desktop for Mac
<https://docs.docker.com/docker-for-mac>`_ following the official
`instructions <https://docs.docker.com/docker-for-mac/install>`__.

.. note::

    Docker Desktop for Mac uses a VM behind the scenes to host the
    Docker runtime environment. By default it allocates 2 GB of RAM to
    the VM. This is not enough to compile Spicy or Zeek and will cause
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

Using Pre-built Docker Images
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We provide a `Docker image <https://hub.docker.com/repository/docker/zeekurity/spicy>`_
with Spicy built from trunk.

To run the image execute the following command::

    docker run -it zeekurity/spicy:latest

Spicy is installed in `/opt/spicy`.

Build Your Own Spicy Container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can build your Spicy container from one of the Docker files coming
with Spicy: Go into Spicy's ``docker`` directory and run ``make`` to
see the container platforms available::

    # cd spicy
    # make

    Run "make build-<platform>", then "make run-<platform>".

    Available platforms:

        alpine-3.12
        centos-8
        ubuntu-18

To build a Spicy container image based on, for example, Ubuntu 18, run::

    # make build-ubuntu-18

Once the container build has finished, you can double-check that the
container image is now available in your local Docker registry::

    # docker images | grep -e spicy -e REPO
    REPOSITORY                                            TAG                 IMAGE ID            CREATED             SIZE
    spicy-ubuntu-18                                       0.2.0-dev           6f48daf3ade3        2 minutes ago       2.45GB
    spicy-ubuntu-18                                       latest              6f48daf3ade3        2 minutes ago       2.45GB

Great, let's fire it up! ::

    # make run-ubuntu-18
    root@bc93113300bc:~# spicyc --version
    0.2.0-dev

.. _building_from_source:

Building from source
--------------------

Prerequisites
~~~~~~~~~~~~~

Spicy currently supports the following platforms:

    - Linux (x86_64)

    - MacOS 10.15 / Catalina

Other platforms are unlikely to work at the moment.

.. note:: Earlier versions of macOS aren't easily supported because of
   their older C++ standard libraries.

To build Spicy, you will need:

    - For compiling the toolchain:

        * A C++ compiler that supports C++17 (known to work are Clang >= 9 and GCC >= 9)
        * `CMake <https://cmake.org>`_  >= 3.13
        * `Bison <https://www.gnu.org/software/bison>`_  >= 3.4
        * `Flex <https://www.gnu.org/software/flex>`_  >= 2.6
        * `Python <https://www.python.org/downloads/>`_ >= 3.4
        * `Zlib <https://www.zlib.net>`_ (no particular version)

    - For integration with Zeek:

        * `Zeek <https://www.zeek.org>`_  >= 3.0

    - For testing:

        * `BTest <https://github.com/zeek/btest>`_  >= 0.66 (``pip install btest``)
        * Bash (for BTest)

    - For building the documentation:

        * `Sphinx <https://www.sphinx-doc.org/en/master>`_  >= 1.8
        * `Pygments <https://pygments.org/>`_  >= 2.5
        * `Read the Docs Sphinx Theme <https://sphinx-rtd-theme.readthedocs.io/en/stable/>`_  (``pip install sphinx_rtd_theme``)

In the following we record how to get these dependencies in place on
some popular platforms. Please :issue:`file an issue <>` if you have
instructions for platforms not yet listed here. Additionally, we provide
Docker files for building on selected Linux distributions, see :ref:`docker`.

.. rubric:: macOS

Make sure you have Xcode installed, including its command tools:
``xcode-select --install``.

If you are using `MacPorts <https://www.macports.org>`_:

    - ``# port install flex bison cmake ninja python38 py38-pip py38-sphinx py38-sphinx_rtd_theme``
    - ``# pip install btest``

If you are using `Homebrew <https://brew.sh>`_:

    - ``# brew install bison flex cmake ninja python@3.8 sphinx-doc``
    - ``# pip3 install btest sphinx_rtd_theme``

In either case, install Zeek >= 3.0 from source, `per the instructions
<https://docs.zeek.org/en/current/install/install.html#installing-from-source>`_

.. rubric:: Linux

On Ubuntu 18 (Bionic):

    - See the :repo:`Ubuntu 18 Docker file <docker/Dockerfile.ubuntu-18>`.

On Alpine 3.12:

    - See the :repo:`Alpine 3.11 Docker file <docker/Dockerfile.alpine-3.12>`.

On CentOS 8 / RedHat 8:

    - See the :repo:`CentOS 8 Docker file <docker/Dockerfile.centos-8>`.


Installing the Spicy Toolchain
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get the code::

   # git clone --recursive https://github.com/zeek/spicy

The short version to install Spicy is the standard ``./configure &&
make && make install``. However, you'll likely need to customize the
build a bit, so we'll walk through some of the options in the
following.

Normally, Spicy's build system will just pick up the system's standard
C++ compiler. If you want to point it to a different compiler, the
``configure`` script provides  an option ``--with-cxx-compiler`` to do
so.

Spicy by default installs into ``/usr/local``. You can change that by
giving ``configure`` a ``--prefix``::

   # ./configure --prefix=/opt/spicy

If Zeek is installed but not in its standard location (i.e.,
``/usr/local/zeek``), you can tell ``configure`` the prefix where to
look for it::

   # ./configure --with-zeek=/opt/zeek

The final ``configure`` output will summarize your build's configuration.
To ensure that Zeek support is enabled, verify the presence of
the following line::

    Zeek plugin enabled:   yes

.. note::

    ``configure`` has a few more flags that may be helpful, see its
    ``--help`` output. For developers, the following may be particular
    useful:

        - ``--enable-debug``: compile a non-optimized debug version
        - ``--enable-sanitizer``: enable address & leak sanitizers
        - ``--generator=Ninja``: use the faster ``ninja`` build system instead of ``make``
        - ``--enable-ccache``: use the ``ccache`` compiler cache to speed up compilation

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
   directory without installing it, the binaries land in ``build/bin``.

To build Spicy's documentation, run ``make`` inside the ``docs/`` directory.
Documentation will be located in ``build/doc/html``.

Development setup
-----------------

In order to speed up precompilation of Spicy parsers, users can create a cache of
precompiled files. This cache is tied to a specific Spicy version, and needs to
be recreated each time Spicy is updated.

To precompile the files execute the following command::

    # spicy-precompile-headers

.. note::

    By default the cache is located in the folder ``.cache/spicy/<VERSION>`` in
    the user's home directory. This location can be overriden by setting the
    environment variable ``SPICY_CACHE`` to a different folder path, both when
    executing ``spicy-precompile-headers`` and Spicy toolchain commands.
