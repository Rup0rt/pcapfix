all:
	gcc $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wno-unused-result pcapfix.c -o pcapfix

install:
	install -D -m 755 pcapfix $(DESTDIR)/usr/bin/pcapfix
	install -D -m 644 pcapfix.1 $(DESTDIR)/usr/share/man/man1/pcapfix.1

uninstall:
	rm -rf /usr/local/bin/pcapfix
	rm -rf /usr/local/man/man1/pcapfix.1

clean:
	rm -rf pcapfix
