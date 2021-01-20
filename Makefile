PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
DOCDIR ?= $(PREFIX)/share/doc
MANDIR ?= $(PREFIX)/share/man

OPTFLAGS = $(shell getconf LFS_CFLAGS) -D_FORTIFY_SOURCE=2 -O2 -fstack-protector --param=ssp-buffer-size=4
WARNFLAGS = -Wall -Wextra -std=gnu99 -pedantic -Wformat -Werror=format-security
DEBUGFLAGS = -g
CFLAGS += $(OPTFLAGS) $(WARNFLAGS) $(DEBUGFLAGS)

# Determine extra LDFLAGS
OS := $(shell uname)
ifeq ($(findstring Darwin,$(OS)),Darwin)
   skip_ldflags = yes
endif
ifeq ($(findstring CYGWIN,$(OS)),CYGWIN)
   skip_ldflags = yes
endif
ifndef skip_ldflags
   LDFLAGS += -Wl,-z,relro
endif

all: pcap pcap_kuznet pcapng
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) pcapfix.c pcap.o pcap_kuznet.o pcapng.o -o pcapfix

pcap: pcap.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c pcap.c -o pcap.o

pcap_kuznet: pcap_kuznet.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c pcap_kuznet.c -o pcap_kuznet.o

pcapng: pcapng.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c pcapng.c -o pcapng.o

.PHONY: install
install:
	install -pDm755 pcapfix $(DESTDIR)$(BINDIR)/pcapfix
	install -pDm644 pcapfix.1 $(DESTDIR)$(MANDIR)/man1/pcapfix.1

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/pcapfix
	rm -f $(DESTDIR)$(MANDIR)/man1/pcapfix.1

clean:
	rm -f *.o
	rm -f pcapfix
