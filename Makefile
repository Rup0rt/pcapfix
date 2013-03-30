all:
	gcc pcapfix.c -o pcapfix

install:
	install -m 755 -d /usr/local/bin/
	install -m 755 -d /usr/local/man/man1
	install -m 755 pcapfix /usr/local/bin/
	install -m 644 pcapfix.1 /usr/local/man/man1/

uninstall:
	rm -rf /usr/local/bin/pcapfix
	rm -rf /usr/local/man/man1/pcapfix.1

clean:
	rm -rf pcapfix
