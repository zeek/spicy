

.. _examples:

========
Examples
========

We collect some example Spicy parsers here that come with the Spicy
distribution.

.. rubric:: TFTP

A TFTP analyzer for Zeek, implementing the original RFC 1350 protocol
(no extensions). It comes with a Zeek script producing a typical
``tftp.log`` log file.

This analyzer is a good introductory example because the Spicy side is
pretty straight-forward. The Zeek-side logging is more tricky because
of the data transfer happening over a separate network session.

    - :repo:`Spicy grammar <spicy/lib/protocols/tftp.spicy>`
    - :repo:`Spicy code for Zeek integration <zeek/plugin/lib/protocols/zeek_tftp.spicy>`
    - :repo:`Zeek analyzer definition (EVT)  <zeek/plugin/lib/protocols/tftp.evt>`
    - :repo:`Zeek TFTP script for logging <zeek/plugin/lib/protocols/tftp.zeek>`

.. rubric:: HTTP

A nearly complete HTTP parser. This parser was used with the original
Spicy prototype to compare output with Zeek's native handwritten HTTP
parser. We observed only negligible differences.

    - :repo:`Spicy grammar <spicy/lib/protocols/http.spicy>`
    - :repo:`Spicy code for Zeek integration <zeek/plugin/lib/protocols/zeek_http.spicy>`
    - :repo:`Zeek analyzer definition (EVT)  <zeek/plugin/lib/protocols/http.evt>`

.. rubric:: DNS

A comprehensive DNS parser. This parser was used with the original
Spicy prototype to compare output with Zeek's native handwritten HTTP
parser. We observed only negligible differences.

The DNS parser is a good example of using :ref:`random access
<random_access>`.

    - :repo:`Spicy grammar <spicy/lib/protocols/dns.spicy>`
    - :repo:`Spicy code for Zeek integration <zeek/plugin/lib/protocols/zeek_dns.spicy>`
    - :repo:`Zeek analyzer definition (EVT)  <zeek/plugin/lib/protocols/dns.evt>`
