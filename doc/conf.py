# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
#
# Configuration file for the Sphinx documentation builder.
#
# This file does only contain a selection of the most common options. For a
# full list see the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import subprocess
import sys

sys.path.insert(0, os.path.abspath("scripts"))

# -- Project information -----------------------------------------------------

project = "Spicy"
copyright = "by the Zeek Project"
author = "Zeek Project"

version = open("../VERSION").readline()
release = "1.15.0"  # most recent release version

# -- General configuration ---------------------------------------------------

needs_sphinx = "1.8"

extensions = ["sphinx.ext.todo", "sphinx.ext.extlinks", "spicy", "spicy-pygments"]

exclude_patterns = [
    "_build",
    "autogen",
    "Thumbs.db",
    ".DS_Store",
    "3rdparty/*",
    "_old-content",
    ".venv",
]

templates_path = ["_templates"]

source_suffix = ".rst"
master_doc = "index"
pygments_style = "sphinx"
highlight_language = "none"

# Todo extension
todo_include_todos = True

# Extlinks extension
extlinks = {
    "repo": (f"https://github.com/zeek/spicy/blob/v{release}/%s", "#%s"),
    "issue": ("https://github.com/zeek/spicy/issues/%s", "#%s"),
    "pr": ("https://github.com/zeek/spicy/pulls/%s", "#%s"),
    "zeek": ("https://docs.zeek.org/en/master/%s", "%s"),
    # Links to binary builds.
    "package-dev-tgz": (
        "https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/%s/packages/build/spicy-dev.tar.gz",
        "%s",
    ),
    "package-dev-rpm": (
        "https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/%s/packages/spicy-dev.rpm",
        "%s",
    ),
    "package-dev-deb": (
        "https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/%s/packages/spicy-dev.deb",
        "%s",
    ),
    "package-release-tgz": (
        f"https://github.com/zeek/spicy/releases/download/v{release}/spicy_%s.tar.gz",
        "%s",
    ),
    "package-release-rpm": (
        f"https://github.com/zeek/spicy/releases/download/v{release}/spicy_%s.rpm",
        "%s",
    ),
    "package-release-deb": (
        f"https://github.com/zeek/spicy/releases/download/v{release}/spicy_%s.deb",
        "%s",
    ),
}

# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"
html_logo = "_static/spicy-logo.png"
html_favicon = "_static/spicy-favicon.ico"
html_title = "Spicy v" + version
html_static_path = ["_static", "doxygen-output"]

html_theme_options = {"style_external_links": True}

linkcheck_ignore = [
    r"https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/.*",
    r"http://download.zeek.org",
    r"https://download.zeek.org",
    # Certificate potentially cannot be validated.
    r"https://www.icir.org/hilti",
]

read_the_docs_build = os.environ.get("READTHEDOCS", None) == "True"
if read_the_docs_build:
    # Generate Doxygen output if we are building in readthedocs. Outside of
    # readthedocs this is done by `docs/Makefile`.
    subprocess.run(["doxygen"], shell=True)
