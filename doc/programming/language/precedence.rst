
.. _precedence:

===================
Operator Precedence
===================

In Spicy, operator precedence is generally pretty similar to other
languages, with some Spicy-specific operators added. The following
table summarizes Spicy's operator precedence, from highest to lowest:

.. list-table:: Operator Precedence
   :widths: 20 80
   :header-rows: 1

   * - Associativity
     - Operators
   * - Left
     - ``.``, ``[``, ``?.``, ``.?``
   * - Right
     - ``!``, ``*`` (unary), ``~``, ``-`` (unary), ``|...|``, ``--``, ``++``
   * - Right
     - ``**``
   * - Left
     - ``%``, ``*``, ``/``
   * - Left
     - ``+``, ``-``
   * - Left
     - ``<<``, ``>>``
   * - Left
     - ``&``
   * - Left
     - ``^``
   * - Left
     - ``|``
   * - Left
     - ``<``, ``>``, ``>=``, ``<=``
   * - Left
     - ``==``, ``!=``
   * - Left
     - ``in``, ``!in``
   * - Left
     - ``&&``
   * - Left
     - ``||``
   * - Left
     - ``?``, ``:``
   * - Left
     - ``=``, ``-=``, ``+=``, ``*=``, ``/=``
