# SPDX-License-Identifier: GPL-2.0-only

INSTALLDIR = $(PREFIX)/bin

.PHONY: shared static install-static install uninstall clean

shared: dbdctl update-img

dbdctl: dbdctl.c
	$(CC) $(CCFLAGS) -o dbdctl -L $(BASE_DIR)/lib dbdctl.c -ldattobd

update-img: update-img.c
	$(CC) $(CCFLAGS) -D_XOPEN_SOURCE=500 -o update-img -L $(BASE_DIR)/lib update-img.c -ldattobd

static: dbdctl-static update-img-static

dbdctl-static: dbdctl.c
	$(CC) $(CCFLAGS) -o dbdctl dbdctl.c $(BASE_DIR)/lib/libdattobd.a

update-img-static: update-img.c
	$(CC) $(CCFLAGS) -D_XOPEN_SOURCE=500 -o update-img update-img.c $(BASE_DIR)/lib/libdattobd.a

install-static: static
	mkdir -p $(INSTALLDIR)
	install dbdctl update-img $(INSTALLDIR)

install: shared
	mkdir -p $(INSTALLDIR)
	install dbdctl update-img $(INSTALLDIR)

uninstall:
	$(RM) $(INSTALLDIR)/dbdctl $(INSTALLDIR)/update-img

clean:
	$(RM) dbdctl update-img
