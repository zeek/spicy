
.. _modules:

=======
Modules
=======

Spicy source code is structured around modules, which
introduce namespaces around other elements defined inside (e.g.,
types, functions). Accordingly, all Spicy input files must start with
``module NAME;``, where ``NAME`` is scope that's being created.

After that initial ``module`` statement, modules may contain arbitrary
list of declarations (types, globals, functions), as well as code
statements to execute. Any code defined at the global level will run
once at the module's initialization time. That's what enables Spicy's
minimal ``hello-world`` module to look like the following:

.. spicy-code:: module-hello-world.spicy

    module Test;

    print "Hello, world!";

.. spicy-output:: module-hello-world.spicy
    :show-with: hello-world.spicy
    :exec: spicyc -j %INPUT

.. _modules_import:

Importing
---------

To make the contents of another module accessible, Spicy provides an
``import NAME;`` statement that pulls in all public identifiers of the
specified external module. Spicy then searches for ``name.spicy``
(i.e., the lower-case version of the imported module ``NAME`` plus a
``.spicy`` extension) along it's module search path. By default,
that's the current directory plus the location where Spicy's pre-built
library modules are installed.

``spicy-config --libdirs`` shows the default search path. The Spicy
tools ``spicy`` && ``spicy-driver`` provide ``--library-path`` options
to add further custom directories. They also allow to fully replace the
built-in default search with a custom value by setting the environment
variable ``SPICY_PATH``.

There's a second version of the import statement that allows to import
from relative locations inside the search path: ``import NAME from
X.Y.Z;`` searches the module ``NAME`` (i.e., ``NAME.spicy``) inside a
sub-directory ``X/Y/Z`` along the search path.

Once Spicy code  has imported a module, it can access identifiers by
prefixing them with the module's namespace:

.. spicy-code::

    import MyModule;

    print MyModule::my_global_variable;

Generally, only identifiers declared as ``public`` become accessible
across module boundaries. The one exception are types, which are
implicitly public.

.. note::

    Spicy makes types implicitly public so that external :ref:`unit
    hooks <unit_hooks>` always have access to them. We may consider a
    more fine-grained model here in the future.

Spicy comes with a set of :ref:`library modules <library>` that you
may import in your code to gain access to their functionality.

Global Properties
-----------------

A module may define the following global properties:

    ``%byte-order = ORDER;``
        Defaults the byte order for any parsing inside this module to
        `<expr>`, where ``ORDER`` must be of type is type
        :ref:`spicy_ByteOrder`.

    ``%spicy-version = "VERSION";``
        Specifies that the module requires a given minimum version of
        Spicy, where ``VERSION`` must be a string of the form ``X.Y``
        or ``X.Y.Z``.

    ``%skip = REGEXP;``
        Specifies a pattern which should be skipped when encountered in the
        input stream in between parsing of unit fields (including before/after
        the first/last field).
    ``%skip-pre = REGEXP;``
        Specifies a pattern which should be skipped when encountered in the
        input stream before parsing of a unit begins.
    ``%skip-post = REGEXP;``
        Specifies a pattern which should be skipped when encountered in the
        input stream after parsing of a unit has finished.
