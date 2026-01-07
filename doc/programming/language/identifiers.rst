
.. _ids:

===========
Identifiers
===========

Spicy distinguishes between different kinds of identifiers:

Declarations
    Identifiers used in declarations of variables, types, functions,
    etc., must start with a letter, and otherwise contain only alphanumerical
    characters and underscores. They cannot match any of :ref:`Spicy's
    built-in keywords <reserved_keywords>`.

Attributes
    Identifiers augmenting other language elements with additional
    *attributes* always begin with `&`. They otherwise follow the same
    rules as identifiers for declarations, except that they also
    permit dashes. Note that you cannot define your own attributes;
    usage is limited to a set of predefined options.

Properties
    Identifiers defining *properties* of modules and types (as in,
    e.g., :ref:`unit_meta_data`) always begin with `%`. They otherwise
    follow the same rules as identifiers for declarations, except that
    they also permit dashes. Note that you cannot define your own
    properties; usage is limited to a set of predefined options.

Identifiers are always case-sensitive in Spicy.
