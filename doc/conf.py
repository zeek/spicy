# -*- coding: utf-8 -*-
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
import sys
import subprocess

sys.path.insert(0, os.path.abspath('scripts'))

# -- Project information -----------------------------------------------------

project = u'Spicy'
copyright = u'2020 by the Zeek Project'
author = u'Zeek Project'

version = subprocess.check_output("../scripts/autogen-version").decode("utf8")
release = "1.0.0" # most recent release version

# -- General configuration ---------------------------------------------------

needs_sphinx = '1.8'

extensions = [
    'sphinx.ext.todo',
    'sphinx.ext.extlinks',
    'spicy',
    'spicy-pygments'
]

exclude_patterns = [u'_build', 'autogen', 'Thumbs.db',
                    '.DS_Store', '3rdparty/*', "_old-content"]

templates_path = ['_templates']

source_suffix = '.rst'
master_doc = 'index'
pygments_style = 'sphinx'
highlight_language = 'none'

# Todo extension
todo_include_todos = True

# Extlinks extension
extlinks = {
    "repo":  ("https://github.com/zeek/spicy/blob/main/%s", "#"),
    "issue": ("https://github.com/zeek/spicy/issues/%s", "#"),
    "pr":    ("https://github.com/zeek/spicy/pulls/%s", "#"),

    # Links to binary builds.
    "package-dev-tgz": ("https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/%s/packages/spicy.tar.gz", ""),
    "package-dev-rpm": ("https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/%s/packages/spicy.rpm", ""),
    "package-dev-deb": ("https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/%s/packages/spicy.deb", ""),
    "package-release-tgz": ("https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/%%s/packages/spicy-%s.tar.gz" % release, ""),
    "package-release-rpm": ("https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/%%s/packages/spicy-%s.rpm" % release, ""),
    "package-release-deb": ("https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/%%s/packages/spicy-%s.deb" % release, "")
}

# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"
html_logo = "_static/spicy-logo.png"
html_favicon = "_static/spicy-favicon.ico"
html_title = "Spicy v" + version
html_static_path = ['_static', 'doxygen-output']

html_theme_options = {
    "style_external_links": True
}

linkcheck_ignore = [
    r'https://api.cirrus-ci.com/v1/artifact/github/zeek/spicy/.*',
    r'http://download.zeek.org',
    r'https://download.zeek.org']

read_the_docs_build = os.environ.get('READTHEDOCS', None) == 'True'
if read_the_docs_build:
    # Fetch complete history if we are build in readthedocs. This is required
    # for `scripts/autogen-version` to work.
    subprocess.run(['git', 'fetch', '--unshallow'], shell=True)
    # Generate Doxygen output if we are building in readthedocs. Outside of
    # readthedocs this is done by `docs/Makefile`.
    subprocess.run(['doxygen'], shell=True)
