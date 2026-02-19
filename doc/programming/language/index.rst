
.. _spicy_language:

========
Language
========

Spicy provides a domain-specific language that consists of two main
types of constructs: parsing elements that capture the layout of an
input format; along with more standard constructs of typical
imperative scripting languages, such as modules, types, declarations,
expressions, etc.. While the :ref:`previous section <parsing>` focuses
on the former, we summarize the more "traditional" parts of Spicy's
language in the following.

We assume some familiarity with other scripting languages. Generally,
where not otherwise stated, think of Spicy as a "C-style scripting
language" in terms of syntax & semantics, with corresponding rules
for, e.g., block structure (``{ ... }``), operator precedence,
identifier naming, etc.. If you are familiar with Zeek's scripting
language in particular, you should be able to get up to speed with
Spicy pretty quickly.

.. toctree::
    :maxdepth: 2

    identifiers
    modules
    functions
    variables
    types
    statements
    precedence
    packing
    conditional
    optimization
    appendix
