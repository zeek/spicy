

.. _examples:

========
Examples
========

We collect some example Spicy parsers here that come with the Spicy
distribution:

:repo:`HTTP <spicy/lib/protocols/http.spicy>`
    A nearly complete HTTP parser. This parser was used with the
    original Spicy prototype to compare output with Zeek's native
    handwritten HTTP parser. We observed only negligible differences.

:repo:`DNS <spicy/lib/protocols/dns.spicy>`
    A comprehensive DNS parser. This parser was used with the
    original Spicy prototype to compare output with Zeek's native
    handwritten HTTP parser. We observed only negligible differences.

    The DNS parser is a good example of using :ref:`random access
    <random_access>`.
