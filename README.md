# Spicy — Robust Parsers for Protocols & File Formats

<table>
  <tr>
    <th></th>
    <th>Stable</th>
    <th>Development</th>
  </tr>
  <tr>
    <td>Documentation</td>
    <td colspan="2" align="center"><a href="https://docs.zeek.org/projects/spicy">Spicy Manual</a></td>
  </tr>
  <tr>
    <td>Changelog</td>
    <td align="center"><a href="https://docs.zeek.org/projects/spicy/en/latest/release-notes.html">Release Notes</td>
    <td align="center"><a href="/CHANGES">CHANGES</a></td>
  </tr>
  <tr>
    <td>Build status</td>
    <td>
      <a href="https://cirrus-ci.com/github/zeek/spicy/release/1.15"><img src="https://api.cirrus-ci.com/github/zeek/spicy.svg?branch=release/1.15" alt="Build status release"></a>
    </td>
    <td>
      <a href="https://cirrus-ci.com/github/zeek/spicy/main"><img src="https://api.cirrus-ci.com/github/zeek/spicy.svg" alt="Build status development"></a>
    </td>
  </tr>
</table>

## Overview <img src='doc/_static/spicy-logo-square.png' align="right" width="150" />

Spicy is a parser generator that makes it easy to create robust C++
parsers for network protocols, file formats, and more. Spicy is a bit
like a "yacc for protocols", but it's much more than that: It's an
all-in-one system enabling developers to write attributed grammars
that describe both syntax and semantics of an input format using a
single, unified language. Think of Spicy as a domain-specific
scripting language for all your parsing needs.

The Spicy toolchain turns such grammars into efficient C++ parsing
code that exposes an API to host applications for instantiating
parsers, feeding them input, and retrieving their results. At runtime,
parsing proceeds fully incrementally—and potentially highly
concurrently—on input streams of arbitrary size. Compilation of Spicy
parsers takes place either just-in-time at startup (through a C++
compiler); or ahead-of-time either by creating pre-compiled shared
libraries, or by giving you generated C++ code that you can link into
your application.

Spicy comes with a [Zeek plugin](https://github.com/zeek/zeek/tree/master/src/spicy)
that enables adding new protocol and file analyzers to
[Zeek](https://www.zeek.org) without having to write any C++ code. You
define the grammar, specify which Zeek events to generate, and Spicy
takes care of the rest. There's also a [Zeek
analyzers](https://github.com/zeek/spicy-analyzers) package that
provides Zeek with several new, Spicy-based analyzers.

See our [collection of example grammars](https://docs.zeek.org/projects/spicy/en/latest/programming/examples.html#examples)
to get a sense of what Spicy looks like.

## Installation

We provide pre-built Spicy binaries for several Linux platforms, as
well as a Homebrew formula (and also binaries) for installation on
macOS. You can also pull a Docker image from Docker Hub, or leverage
one of several included Docker files as a starting point. Of course,
you can also just build Spicy from source directly. See the
[installation
instructions](https://docs.zeek.org/projects/spicy/en/latest/installation.html)
for more information on any of these options.


## Documentation

Please read the [Spicy Manual](https://docs.zeek.org/projects/spicy),
which provides the following sections:

* [Installation](https://docs.zeek.org/projects/spicy/en/latest/installation.html)
* [Getting Started](https://docs.zeek.org/projects/spicy/en/latest/getting-started.html)
* [FAQ](https://docs.zeek.org/projects/spicy/en/latest/faq.html)
* [Tutorial: A Real Analyzer](https://docs.zeek.org/projects/spicy/en/latest/tutorial/index.html)
* [Programming in Spicy](https://docs.zeek.org/projects/spicy/en/latest/programming/index.html)
* [Toolchain](https://docs.zeek.org/projects/spicy/en/latest/toolchain.html)
* [Zeek Integration](https://docs.zeek.org/projects/spicy/en/latest/zeek.html)
* [Custom Host Applications](https://docs.zeek.org/projects/spicy/en/latest/host-applications.html)
* [Release Notes](https://docs.zeek.org/projects/spicy/en/latest/release-notes.html)
* [Developer's Manual](https://docs.zeek.org/projects/spicy/en/latest/development/index.html)


## Getting in touch

Having trouble using Spicy? Have ideas how to make Spicy better? We'd
like to hear from you!

- Report issues on the GitHub [ticket tracker](https://github.com/zeek/spicy/issues).

- Ask the `#spicy` channel [on Zeek's Slack](https://zeek.org/slack).

- Check out the [Zeek community](https://community.zeek.org) and discuss Spicy under
  the [Spicy tag](https://community.zeek.org/c/spicy/).

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
