all:
	gcc pcapfix.c -o pcapfix

install:
	cp pcapfix /usr/local/bin/
	cp pcapfix.1 /usr/local/man/man1/
	updatedb

uninstall:
	rm -rf /usr/local/bin/pcapfix
	rm -rf /usr/local/man/man1/pcapfix.1

clean:
	rm -rf pcapfix
