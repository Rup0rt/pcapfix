PREFIX = /usr
BINDIR = $(PREFIX)/bin
DOCDIR = $(PREFIX)/share/doc
MANDIR = $(PREFIX)/share/man

OPTFLAGS = $(shell getconf LFS_CFLAGS)
#WARNFLAGS = -Wno-unused-result
WARNFLAGS = -Wall
DEBUGFLAGS = -g
CFLAGS += $(OPTFLAGS) $(WARNFLAGS) $(DEBUGFLAGS)

all:
	gcc $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) pcapfix.c -o pcapfix

install:
	install -D -m 755 pcapfix $(DESTDIR)/$(BINDIR)/pcapfix
	install -D -m 644 pcapfix.1 $(DESTDIR)/$(MANDIR)/man1/pcapfix.1

uninstall:
	rm -f $(DESTDIR)/$(BINDIR)/pcapfix
	rm -f $(DESTDIR)/$(MANDIR)/man1/pcapfix.1

clean:
	rm -f pcapfix
