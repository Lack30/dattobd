# SPDX-License-Identifier: GPL-2.0-only

export CC = gcc
export RM = rm -f
CFLAGS ?= -Wall
export CCFLAGS = $(CFLAGS) -std=gnu99
export PREFIX = /usr/local
export BASE_DIR = $(abspath .)

BUILDDIR := $(CURDIR)/pkgbuild

# Flags to pass to debbuild/rpmbuild
PKGBUILDFLAGS := --define "_topdir $(BUILDDIR)" -ba --with devmode

# Command to create the build directory structure
PKGBUILDROOT_CREATE_CMD = mkdir -p $(BUILDDIR)/DEBS $(BUILDDIR)/SDEBS $(BUILDDIR)/RPMS $(BUILDDIR)/SRPMS \
			$(BUILDDIR)/SOURCES $(BUILDDIR)/SPECS $(BUILDDIR)/BUILD $(BUILDDIR)/BUILDROOT

.PHONY: all driver library-shared library-static library application application-shared clean install uninstall pkgclean pkgprep deb rpm

all: driver library application

driver:
	$(MAKE) -C src

library-shared:
	$(MAKE) -C lib CCFLAGS="$(CCFLAGS) -I$(BASE_DIR)/src" shared

library-static:
	$(MAKE) -C lib CCFLAGS="$(CCFLAGS) -I$(BASE_DIR)/src" static

library: library-shared library-static

application-static: library-static
	$(MAKE) -C app CCFLAGS="$(CCFLAGS) -I$(BASE_DIR)/src -I$(BASE_DIR)/lib"

application: library-shared
	$(MAKE) -C app CCFLAGS="$(CCFLAGS) -I$(BASE_DIR)/src -I$(BASE_DIR)/lib" shared

clean:
	$(MAKE) -C src clean
	$(MAKE) -C lib clean
	$(MAKE) -C app clean

pkgclean:
	rm -rf $(BUILDDIR)

pkgprep: pkgclean
	$(PKGBUILDROOT_CREATE_CMD)
	tar --exclude=./pkgbuild --exclude=.git --transform 's,^\.,dattobd,' -czf $(BUILDDIR)/SOURCES/dattobd.tar.gz .
	cp dist/dattobd.spec $(BUILDDIR)/SPECS/dattobd.spec

deb: pkgprep
	debbuild $(PKGBUILDFLAGS) $(BUILDDIR)/SPECS/dattobd.spec

rpm: pkgprep
	rpmbuild $(PKGBUILDFLAGS) $(BUILDDIR)/SPECS/dattobd.spec

install:
	$(MAKE) -C src install
	$(MAKE) -C lib install CCFLAGS="$(CCFLAGS) -I$(BASE_DIR)/src"
	$(MAKE) -C app install CCFLAGS="$(CCFLAGS) -I$(BASE_DIR)/src -I$(BASE_DIR)/lib"

uninstall:
	$(MAKE) -C app uninstall
	$(MAKE) -C lib uninstall
	$(MAKE) -C src uninstall
