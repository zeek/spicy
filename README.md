# Spicy — Generating Parsers for Protocols & Files

<table><tr>

<td width="66%">
<ul>
<li><a href="#overview-">Overview</a></li>
<li><a href="#installation">Installation</a></li>
<li><a href="#documentation">Documentation</a></li>
<li><a href="#getting-in-touch">Getting in touch</a></li>
<li><a href="#status">Status</a></li>
<li><a href="#license">License</a></li>
<li><a href="#history">History</a></li>
</ul>
</td>

<td>
<table>
<tr><th></th>                 <th> <code>master</code> </th> </tr>
<tr><td> Documentation </td>  <td> <a href="https://docs.zeek.org/projects/spicy">Spicy Manual</a> </td></tr>
<tr><td> Changelog </td>      <td> <a href="/CHANGES">CHANGES </a> </td></tr>
<tr><td> Build status </td>   <td> <a href="https://cirrus-ci.com/github/zeek/spicy/master"><img src="https://api.cirrus-ci.com/github/zeek/spicy.svg" alt="Build status"> </a> </td></tr>
</table>
</td>

</table>

## Overview <img src='doc/_static/spicy-logo-square.png' align="right" width="150" />

Spicy is a C++ parser generator that makes it easy to create robust
parsers for network protocols, file formats, and more. Spicy is a bit
like a "yacc for protocols", but it's much more than that: It's an
all-in-one system enabling developers to write attributed grammars
that define both syntax and semantics of an input format using a
single, unified language. Think of Spicy as a domain-specific
scripting language for all your parsing needs.

The Spicy toolchain turns such grammars into efficient C++ parsing
code that exposes an API to host applications for instantiating
parsers, feeding them input, and retrieving their results. At runtime,
parsing proceeds fully incrementally—and potentially highly
concurrently—on input streams of arbitrary size. Compilation of Spicy
parsers takes place either just-in-time at startup (through a C++
compiler), or ahead-of-time either by creating pre-compiled shared
libraries or simply by giving you C++ code that you can link into your
application.

Spicy comes with a [Zeek](https://www.zeek.org) plugin that enables
adding new protocols to Zeek without having to write any C++ code. You
define the grammar, specify which Zeek events to generate, and Spicy
takes care of the rest.


## Installation

While there are no dedicated releases yet, we provide pre-built Spicy
binaries for some Linux platforms as well as a Homebrew formula for
installation on macOS. You can also use one of the included Docker
files, or just build Spicy from source directly. See the [installation
instructions](https://docs.zeek.org/projects/spicy/en/latest/installation.html)
for more information on any of these options.

## Documentation

Please read the [Spicy Manual](https://docs.zeek.org/projects/spicy),
which provides the following sections:

* [Installation](https://docs.zeek.org/projects/spicy/en/latest/installation.html)
* [Getting Started](https://docs.zeek.org/projects/spicy/en/latest/getting-started.html)
* [FAQ](https://docs.zeek.org/projects/spicy/en/latest/faq.html)
* [Tutorial: A Real Analyzer](https://docs.zeek.org/projects/spicy/en/latest/tutorial/index.html) (Missing)
* [Programming in Spicy](https://docs.zeek.org/projects/spicy/en/latest/programming/index.html)
* [Toolchain](https://docs.zeek.org/projects/spicy/en/latest/toolchain.html)
* [Zeek Integration](https://docs.zeek.org/projects/spicy/en/latest/zeek.html)
* [Release Notes](https://docs.zeek.org/projects/spicy/en/latest/release-notes.html)
* [Developer's Manual](https://docs.zeek.org/projects/spicy/en/latest/development/index.html)


## Getting in Touch

Having trouble using Spicy? Have ideas how to make Spicy better? We'd
like to hear from you!

- Report issues on [GitHub](https://github.com/zeek/spicy/issues).

- Ask the `#spicy` channel [on Zeek's Slack](https://zeek.org/connect).

- Subscribe to the [Spicy mailing list](https://lists.zeek.org/mailman3/lists/spicy.lists.zeek.org)

- To follow development, subscribe to the [commits mailing
  list](https://lists.zeek.org/mailman3/lists/spicy-commits.lists.zeek.org) (it can
  be noisy).


## Status

Spicy is currently in a very early beta phase, it's *not* yet ready
for production usage. You'll find plenty rough edges still, including
unstable code, missing features, and confusing error messages if you
do something unexpected. Specifics of the language and the toolchain
may still change as well—there's no release yet, just a git `master`
branch that keeps moving. We don't recommend Spicy and its parsers for
anything critical yet, but we're very interested in feedback as we're
working to stabilize all this.


## License

Spicy is open source and released under a BSD license, which allows
for pretty much unrestricted use as long as you leave the license
header in place. You fully own any parsers that Spicy generates from
your grammars.


## History

Spicy was originally developed as a research prototype at the
[International Computer Science Institute](http://www.icsi.berkeley.edu)
with funding from the [U.S. National Science Foundation](https://www.nsf.gov).
Since then, Spicy has been rebuilt from the ground up by
[Corelight](https://www.corelight.com), which has contributed the new
implementation to the Zeek Project.
