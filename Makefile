all:
	gcc pcapfix.c -o pcapfix

install:
	cp pcapfix /usr/local/bin/

uninstall:
	rm -rf /usr/local/bin/pcapfix

clean:
	rm -rf pcapfix
