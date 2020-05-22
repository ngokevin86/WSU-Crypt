Project - wsu-crypt

NOTES:
-Please do not copy and use my code! You are welcome to reference it.
-There's a lot of inefficiencies in the encryption phase, which may eventually be worked on and redone.

Included files:
wsu-crypt.c - Program source code
Makefile - A make file for compiling the source code
README.txt - This file

To compile, have required files
	wsu-crypt.c
	Makefile
in the same director, and use the command
	make
	OR
	gcc -o wsu-crypt wsu-crypt.c -lm
to compile wsu-crypt.c

To run, use the command format
	./wsu-crypt <plaintext/ciphertext> <keytext> <e/d>
where
	<plaintext/ciphertext>
	is any .txt file where
		<plaintext>
	is filled with ASCII characters and
		<ciphertext>
	is filled with valid hex characters
and
	<keytext>
	is a .txt file with at least 64-bits total of valid hex characters
	(will not use more than the first 64-bits)
and
	<e/d>
	is either encrypt (e)
	or decrypt (d)
Example commands for encryption and decryption are included at the bottom of this README.

Output for encryption will be named "ciphertext.txt"
while for decryption will be named "plaintext.txt"

Notes:
-The program will not run if a pre-existing "plaintext.txt" or "ciphertext.txt" exists when
	encrypting or decrypting, respectively. In this case, the user will be warned.
-If a character that isn't "e" or "d" is used, or no character is supplied, the user will be warned of the correct input.
-The key file is expected to hold AT LEAST 64-bits of valid hex. It will not use any additional hex.
-plaintext.txt may have additional "0x00" padding at the end if the original text was not exactly a multiple
	of 64-bits long.
-Set DEBUG to 1 in wsu-crypt.c (and recompile) to see debug information similar to that seen in "Test Vector 1" and "Test Vector 2"
-Set TV2 to 1 in wsu-crypt.c (and recompile) to encrypt/decrypt similar to "Test Vector 2". Know that the result from decrypting
	will be in ASCII test and is not "human readable".
	-Additionally, for encryption, just use any plaintext file that has exactly (or less than) 64-bits.
		-Such as "01234567"

Example command for encryption:
	./wsu-crypt plaintext.txt key.txt e
where "plaintext.txt" contains "Hello world! I am doing fine."
where "key.txt" contains "abcdef0123456789"
where "e" is to encrypt
Output is "ciphertext.txt" which contains "93395160d66e41c342ac5f69cff67f803b02860dcbd1d351992e7d1e3b951fd3"

Example command for decryption:
	./wsu-crypt ciphertext.txt key.txt d
where "ciphertext.txt" contains "93395160d66e41c342ac5f69cff67f803b02860dcbd1d351992e7d1e3b951fd3"
where "key.txt" contains "abcdef0123456789"
where "d" is to decrypt
Output is "plaintext.txt" which contains "Hello world! I am doing fine.\00\00\00"
(note the additional padding as noted previously)
