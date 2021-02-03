# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    = -W --keep-going -n
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = Spicy
BUILDDIR      = $(PWD)/../build
SOURCEDIR     = $(PWD)
DESTDIR       = $(BUILDDIR)/html

all: html

clean:
	rm -rf $(DESTDIR)

html: autogen-docs sphinx

sphinx:
	@rm -f "$(BUILDDIR)/doc-root" && ln -s "../doc" "$(BUILDDIR)/doc-root"
	@  # Since Sphinx expects the Doxygen output directory, create it here to
	@  # allow users to build without Doxygen, but still have Sphinx succeed.
	@mkdir -p doxygen-output
	@  # The RTD theme might be producing RemovedInSphinx30Warning
	@PYTHONWARNINGS="ignore" PATH=$(BUILDDIR)/bin:$$PATH $(SPHINXBUILD) -M html "$(SOURCEDIR)" "$(DESTDIR)" $(SPHINXOPTS) $(O)
	@echo Built documentation in $(realpath $(DESTDIR)/html/index.html)

autogen-docs:
	@echo Auto-generating reference documentation ...
	(cd $(BUILDDIR)/.. && ./doc/scripts/autogen-docs)

doxygen:
	mkdir -p ../build/html/html/doxygen
	doxygen

check:
	@$(SPHINXBUILD) -q -b linkcheck $(SOURCEDIR) $(DESTDIR)/linkcheck

.PHONY: autogen-docs check doxygen
