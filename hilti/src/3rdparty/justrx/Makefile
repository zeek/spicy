# $Id$
#
# Build libhilti

all: do-build

do-build:
	test -e build || mkdir build
	cd build; test -e Makefile || cmake .. ; make

clean:
	rm -rf build

