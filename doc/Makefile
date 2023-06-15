# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    = -W --keep-going -n
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = Spicy
BUILDDIR      = $(PWD)/../build
SOURCEDIR     = $(PWD)
DESTDIR       = $(BUILDDIR)/html

.PHONY: all
all: html

.PHONY: clean
clean:
	rm -rf $(DESTDIR)

.PHONY: html
html: autogen-docs sphinx

.PHONY: livehtml
livehtml: autogen-docs sphinx-auto

.PHONY: sphinx-setup
sphinx-setup:
	@rm -f "$(BUILDDIR)/doc-root" && ln -s "../doc" "$(BUILDDIR)/doc-root"
	@  # Since Sphinx expects the Doxygen output directory, create it here to
	@  # allow users to build without Doxygen, but still have Sphinx succeed.
	@mkdir -p doxygen-output

.PHONY: sphinx
sphinx: sphinx-setup
	@  # The RTD theme might be producing RemovedInSphinx30Warning
	@PYTHONWARNINGS="ignore" PATH=$(BUILDDIR)/bin:$$PATH $(SPHINXBUILD) -M html "$(SOURCEDIR)" "$(DESTDIR)" $(SPHINXOPTS) $(O)
	@echo Built documentation in $(realpath $(DESTDIR)/html/index.html)

.PHONY: sphinx-auto
sphinx-auto: sphinx-setup
	sphinx-autobuild --ignore "*.git/*" --ignore "*.lock" --ignore "*.pyc" --ignore "*.swp" --ignore "*.swpx" --ignore "*.swx" -b html -d "$(DESTDIR)/doctrees" "$(SOURCEDIR)" "$(DESTDIR)/html"

.PHONY: autogen-docs
autogen-docs:
	@echo Auto-generating reference documentation ...
	(cd $(BUILDDIR)/.. && ./doc/scripts/autogen-docs)

.PHONY: doxygen
doxygen:
	mkdir -p ../build/html/html/doxygen
	doxygen

.PHONY: check
check:
	@$(SPHINXBUILD) -q -b linkcheck $(SOURCEDIR) $(DESTDIR)/linkcheck


spicy-%:
	git clone https://github.com/zeek/$@
zeek:
	git clone https://github.com/zeek/zeek --depth 1

check-zeek-docs: spicy-tftp zeek
	@echo Refreshing checkouts
	@for REPO in $^; do (cd $$REPO && git pull && git reset HEAD --hard)>/dev/null; done
	@
	@echo Checking whether docs for Zeek integration are up-to-date
	@./scripts/autogen-zeek-docs zeek spicy-tftp
	@
	@git diff --quiet autogen/zeek \
		|| (echo "Zeek docs are not up-to-date, rerun './scripts/autogen-zeek-docs'." && exit 1)
