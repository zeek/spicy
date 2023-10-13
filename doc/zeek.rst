
.. _zeek_plugin:

================
Zeek Integration
================

While Spicy itself remains application independent, transparent
integration into `Zeek <https://zeek.org>`_ has been a primary goal
for its development from early on. While historically an external Zeek
plugin was required to use Spicy parsers with Zeek, Zeek has now been
shipping with built-in Spicy support since version 5.0. That means you
can directly add new protocol, file, and packet analyzers to Zeek
through Spicy without needing to write any further code. See
:zeek:`Zeek's Spicy documentation <devel/spicy/index.html>` for more.
