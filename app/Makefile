# SPDX-License-Identifier: GPL-2.0-only

INSTALLDIR = $(PREFIX)/bin

.PHONY: shared static install-static install uninstall clean

shared: dbdctl update-img dbdbcsd apply-bcslog

dbdctl: dbdctl.c
	$(CC) $(CCFLAGS) -o dbdctl -L $(BASE_DIR)/lib dbdctl.c -ldattobd

update-img: update-img.c
	$(CC) $(CCFLAGS) -D_XOPEN_SOURCE=500 -o update-img -L $(BASE_DIR)/lib update-img.c -ldattobd

dbdbcsd: dbdbcsd.c
	$(CC) $(CCFLAGS) -o dbdbcsd -L $(BASE_DIR)/lib dbdbcsd.c -ldattobd

apply-bcslog: apply-bcslog.c
	$(CC) $(CCFLAGS) -o apply-bcslog -L $(BASE_DIR)/lib apply-bcslog.c -ldattobd

static: dbdctl-static update-img-static dbdbcsd-static apply-bcslog-static

dbdctl-static: dbdctl.c
	$(CC) $(CCFLAGS) -o dbdctl dbdctl.c $(BASE_DIR)/lib/libdattobd.a

update-img-static: update-img.c
	$(CC) $(CCFLAGS) -D_XOPEN_SOURCE=500 -o update-img update-img.c $(BASE_DIR)/lib/libdattobd.a

dbdbcsd-static: dbdbcsd.c
	$(CC) $(CCFLAGS) -o dbdbcsd dbdbcsd.c $(BASE_DIR)/lib/libdattobd.a

apply-bcslog-static: apply-bcslog.c
	$(CC) $(CCFLAGS) -o apply-bcslog apply-bcslog.c $(BASE_DIR)/lib/libdattobd.a

install-static: static
	mkdir -p $(INSTALLDIR)
	install dbdctl update-img dbdbcsd apply-bcslog $(INSTALLDIR)

install: shared
	mkdir -p $(INSTALLDIR)
	install dbdctl update-img dbdbcsd apply-bcslog $(INSTALLDIR)

uninstall:
	$(RM) $(INSTALLDIR)/dbdctl $(INSTALLDIR)/update-img $(INSTALLDIR)/dbdbcsd $(INSTALLDIR)/apply-bcslog

clean:
	$(RM) dbdctl update-img dbdbcsd apply-bcslog
