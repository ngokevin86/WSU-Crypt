#Kevin Ngo
#Project - WSU Crypt (Makefile)

all: wsu-crypt.c
	gcc -o wsu-crypt wsu-crypt.c -lm

run: wsu-crypt
	./wsu-crypt

clean:
	rm -f wsu-crypt *.o