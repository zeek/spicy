
.. _coding_style:

Style
=====

.. todo:: This is very preliminary. We'll extend it over time. It's
   also not consistently applied everywhere yet. Working on that.

.. _tooling:

Tooling
-------

Spicy ships with a set of linter configurations to enforce some of the style
guidelines documented below. We use `pre-commit <https://pre-commit.com/>`__ to
run linters on each commit.

After cloning the repository, one can install the commit hooks by running the
following command from the root of the checkout::

    $ pre-commit install && pre-commit install --hook-type commit-msg
    pre-commit installed at .git/hooks/pre-commit
    pre-commit installed at .git/hooks/commit-msg

With installed hooks the configured linters check the code after each
commit. To run linters standalone one can use the following::

    $ pre-commit run -a

See the `pre-commit CLI documentation <https://pre-commit.com/#cli>`__ for more
information on how pre-commit can be used.

.. note::

    Some linters might require that a full build was performed or additional
    external tooling, see e.g., :ref:`clang_format`.

Commit Messages
---------------

- Provide meaningful commit messages. Start the commit message with a
  one line summary and then explain at a high-level what's going on,
  including in particular any new functionality and changes to
  existing semantics. Include short examples of functionality if
  possibles. (Expect people to read your commit messages. :)

- If the commit refers to ticket or PR, include the number into the
  commit message.

- Aim to make commits self-containing chunks of functionality. Rebase
  and squash before pushing upstream.

- Formatting aspects of commit messages are linted with `gitlint
  <https://jorisroovers.com/gitlint/>`__ via pre-commit hooks, see
  :ref:`tooling`. In particular we enforce that summary lines start with a
  capital letter and end in a period, and length limits for both summary and
  body lines.

.. _clang_format:

Formatting
----------

Spicy comes with a ``clang-format`` configuration that enforces a canonical
style. We require ``clang-format`` version >= 10 because we need a style option
that wasn't available earlier. Formatting is checked by a ``clang-format``
linter which automatically pulls in a suitable ``clang-format`` binary, see the
:ref:`tooling` section.

Spicy's CI runs ``pre-commit run clang-format`` as part of its code checks and will
abort if there's anything not formatted as expected.

.. _clang_tidy:

Static analysis
---------------

Spicy also comes with a ``clang-tidy`` configuration, as well as
``Makefile`` targets similar to the ones for formatting: ``make tidy``
will check the code, and ``make tidy-fixit`` will apply fixes
automatically where ``clang-tidy`` is able to. Note that the latter
can sometimes make things worse: Double-check ``git diff`` before
committing anything.

You can set the environment variable ``CLANG_TIDY`` to the full path
of the ``clang-tidy`` to ensure the right version is found (which,
similar to ``clang-format``, needs to be from Clang >= 10).

Spicy's CI runs ``make tidy`` as part of its code checks and will
abort if there's anything not formatted as expected.

Code Conventions
----------------

.. rubric:: Identifiers

- Class methods: ``lowerCamelCase()`` for public and protected methods;
  ``_lowerCamelCase()`` for private methods.

- Class member constants & variables: ``lower_case`` for public
  members, and ``_lower_case_with_leading_underscore`` for private
  members.

- Global function: ``lowerCamelCase()``

.. rubric:: Comments

- In header files:

    - Public namespace (i.e., anything *not* in ``*::detail::*``)

        * Add Doxygen comments to all namespace elements.

        * Add Doxygen comments to all ``public`` and ``protected``
          members of classes. (Exceptions: Default constructors;
          destructors; ``default`` operators; "obvious" operators, such
          as basic constructors and straight-forward comparisons;
          obvious getters/setters).

    - Private namespace (i.e., anything in ``*::detail::*``)

        * Add a brief sentence or two to all namespace elements that
          aren't obvious.

        * Add a brief sentence or two to all class members that aren't
          obvious.

- In implementation files

    - For elements that aren't declared in a separate header file,
      follow the rules for headers defining elements of the private
      namespace.

    - Inside methods and functions, comment liberally but not
      needlessly. Briefly explain the main reasoning behind
      non-obvious logic, and introduce separate parts inside larger
      chunks of code.

.. rubric:: Doxygen style

* Always start with a brief one-sentence summary in active voice
  ("Changes X to Y.")

* For functions and methods, include ``@param`` and ``@return`` tags
  even if it seems obvious what's going on. Add ``@throws`` if the
  function/method raises an exception in a way that's considered part
  of its specific semantics.
