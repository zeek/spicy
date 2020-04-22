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

html: Makefile autogen-docs
	@rm -f "$(BUILDDIR)/doc-root" && ln -s "../doc" "$(BUILDDIR)/doc-root"
	@  # The RTD theme might be producing RemovedInSphinx30Warning
	@PYTHONWARNINGS="ignore" $(SPHINXBUILD) -M html "$(SOURCEDIR)" "$(DESTDIR)" $(SPHINXOPTS) $(O)
	@echo Built documentation in $(DESTDIR)/html/index.html

autogen-docs:
	@echo Auto-generating reference documentation ...
	(cd $(BUILDDIR)/.. && ./doc/scripts/autogen-docs)

.PHONY: Makefile autogen-docs
