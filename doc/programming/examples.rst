

.. _examples:

========
Examples
========

We collect some example Spicy parsers here that come with a growing collection
of `Spicy-based Zeek analyzers <https://github.com/zeek/spicy-analyzers>`_.
Check out that package and `its dependencies
<https://github.com/zeek/spicy-analyzers/blob/main/zkg.meta>`_ for more
examples.

.. rubric:: TFTP

A TFTP analyzer for Zeek, implementing the original RFC 1350 protocol
(no extensions). It comes with a Zeek script producing a typical
``tftp.log`` log file.

This analyzer is a good introductory example because the Spicy side is
pretty straight-forward. The Zeek-side logging is more tricky because
of the data transfer happening over a separate network session.

    - `TFTP Spicy grammar <https://github.com/zeek/spicy-tftp/blob/main/analyzer/tftp.spicy>`_
    - `TFTP Zeek analyzer definition (EVT) <https://github.com/zeek/spicy-tftp/blob/main/analyzer/tftp.evt>`_
    - `Zeek TFTP script for logging <https://github.com/zeek/spicy-tftp/blob/main/scripts/main.zeek>`_

.. rubric:: HTTP

A nearly complete HTTP parser. This parser was used with the original
Spicy prototype to compare output with Zeek's native handwritten HTTP
parser. We observed only negligible differences.

    - `HTTP Spicy grammar <https://github.com/zeek/spicy-http/blob/main/analyzer/analyzer.spicy>`_
    - `Spicy code for HTTP analyzer Zeek integration <https://github.com/zeek/spicy-http/blob/main/analyzer/zeek_analyzer.spicy>`_
    - `HTTP Zeek analyzer definition (EVT)  <https://github.com/zeek/spicy-http/blob/main/analyzer/analyzer.evt>`_

.. rubric:: DNS

A comprehensive DNS parser. This parser was used with the original
Spicy prototype to compare output with Zeek's native handwritten DNS
parser. We observed only negligible differences.

The DNS parser is a good example of using :ref:`random access
<random_access>`.

    - `DNS Spicy grammar <https://github.com/zeek/spicy-dns/blob/main/analyzer/analyzer.spicy>`_
    - `Spicy code for DNS analyzer Zeek integration <https://github.com/zeek/spicy-dns/blob/main/analyzer/zeek_analyzer.spicy>`_
    - `DNS Zeek analyzer definition (EVT)  <https://github.com/zeek/spicy-dns/blob/main/analyzer/analyzer.evt>`_

.. rubric:: DHCP

A nearly complete DHCP parser. This parser extracts most DHCP option
messages understood by Zeek. The Zeek integration is almost direct and
most of the work is in formulating the parser itself.

    - `DHCP Spicy grammar <https://github.com/zeek/spicy-dhcp/blob/main/analyzer/analyzer.spicy>`_
    - `Spicy code for DHCP analyzer Zeek integration <https://github.com/zeek/spicy-dhcp/blob/main/analyzer/zeek_analyzer.spicy>`_
    - `DHCP analyzer Zeek analyzer definition (EVT)  <https://github.com/zeek/spicy-dhcp/blob/main/analyzer/analyzer.evt>`_
