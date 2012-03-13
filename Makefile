all:
	gcc pcapfix.c -o pcapfix

install:
	cp pcapfix /usr/local/bin/

clean:
	rm -rf pcapfix
