

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

    - `TFTP Spicy grammar <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/tftp/tftp.spicy>`_
    - `Spicy code for Zeek integration <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/tftp/zeek_tftp.spicy>`
    - `Zeek analyzer definition (EVT) <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/tftp//tftp.evt>`
    - `Zeek TFTP script for logging <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/tftp//tftp.zeek>`

.. rubric:: HTTP

A nearly complete HTTP parser. This parser was used with the original
Spicy prototype to compare output with Zeek's native handwritten HTTP
parser. We observed only negligible differences.

    - `HTTP Spicy grammar <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/http/http.spicy>`_
    - `Spicy code for Zeek integration <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/http//zeek_http.spicy>`
    - `Zeek analyzer definition (EVT)  <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/http/http.evt>`

.. rubric:: DNS

A comprehensive DNS parser. This parser was used with the original
Spicy prototype to compare output with Zeek's native handwritten DNS
parser. We observed only negligible differences.

The DNS parser is a good example of using :ref:`random access
<random_access>`.

    - `DNS Spicy grammar <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/dns/dns.spicy>`_
    - `Spicy code for Zeek integration <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/dns/zeek_dns.spicy>`
    - `Zeek analyzer definition (EVT)  <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/dns/dns.evt>`

.. rubric:: DHCP

A nearly complete DHCP parser. This parser extracts most DHCP option
messages understood by Zeek. The Zeek integration is almost direct and
most of the work is in formulating the parser itself.

    - `DHCP Spicy grammar <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/dhcp/dhcp.spicy>`_
    - `Spicy code for Zeek integration <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/dhcp/zeek_dhcp.spicy>`
    - `Zeek analyzer definition (EVT)  <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/protocol/dhcp/dhcp.evt>`
