
.. _modules:

=======
Modules
=======

Spicy source code is structured around modules, which essentially
introduce namespaces around other elements defined inside (e.g.,
types, functions). Accordingly, all Spicy input files must start with
``module NAME;``, where ``NAME`` is scope that's being created.

After that initial ``module`` statement, modules may contain arbitrary
list of declarations (types, globals, functions), as well as code
statement to execute. Any code defined at the global level will run
once at the module's initialization time. That's what gives us Spicy's
minimal ``hello-world`` module:

.. spicy-code:: module-hello-world.spicy

    module Test;

    print "Hello, world!";

.. spicy-output:: module-hello-world.spicy
    :show-with: hello-world.spicy
    :exec: spicyc -j %INPUT

.. _modules_import:

To make the contents of another module accessible, Spicy provides an
``import NAME;`` statement that pulls in all public identifiers of the
specified external module. Spicy searches for ``NAME`` along it's
module search path. By default, that's the current directory plus the
location where Spicy's pre-built library modules are installed. To
find the module in one of those directories, its filename must be
``NAME.spicy``, with case-sensitive matching

``spicy-config --libdirs`` shows the default search path. The Spicy
tools ``spicy`` && ``spicy-driver`` provide ``--library-path`` options
to add further custom directories.

.. todo::

    Actually ``spicy-driver`` does not have that option yet
    (:issue:`88`). And we should also add an environment variable
    ``SPICY_PATH``.

There's a second version of the import statement that allows to import
from relative locations inside the search path: ``import NAME from
X.Y.Z;`` searches the module ``NAME`` (i.e., ``NAME.spicy``) inside a
sub-directory ``X/Y/Z`` along the search path.

Once Spicy code  has imported a module, it can access identifiers by
prefixing them with the module's namespace::

    import MyModule;

    print MyModule::my_global_variable;

Note that only identifiers declared as ``public`` become accessible
across module boundaries.
