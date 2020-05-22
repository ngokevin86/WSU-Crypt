#Kevin Ngo - CS 427
#Project 1 - WSU Crypt (Makefile)
#Professor Farhana Kabir
#Due March 1st

all: wsu-crypt.c
	gcc -o wsu-crypt wsu-crypt.c -lm

run: wsu-crypt
	./wsu-crypt

clean:
	rm -f wsu-crypt *.o