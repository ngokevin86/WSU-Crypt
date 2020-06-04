/* Kevin Ngo
 * Project - WSU Crypt (Source File)
 */

/*wsu-crypt.c
	This program takes three inputs, a plaintext/ciphertext file, a key file, and a boolean.
	The first input can either be a plaintext file in ASCII, or a ciphertext file in hex.
	The second input MUST have an 8 Byte (64-bit) hex key in it.
	The third input can either be 
		"e" for encryption (take plaintext, generate ciphertext)
		"d" for decryption (take ciphertext, rebuild plaintext)
	The output for these modes is "ciphertext.txt" and "plaintext.txt", respectively.
 
	Notes:
	-The program will not run if a pre-existing "plaintext.txt" or "ciphertext.txt" exists when
		encrypting or decrypting, respectively.
	-The key file is expected to hold at least 64-bits of valid hex. It will not use any additional hex.
	-plaintext.txt may have additional "0x00" padding at the end if the original text was not exactly a multiple
		of 64-bits long.
	-Set DEBUG to 1 (and recompile) to see debug information
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <errno.h>
#include <stdint.h>

#define DEBUG 1

//struct for function F return value
struct blockStruct{
	unsigned int word1;
	unsigned int word2;
	unsigned int word3;
	unsigned int word4;
};

//struct for subkeys generated each round
struct subkeyStruct{
	int k0;
	int k1;
	int k2;
	int k3;
	int k4;
	int k5;
	int k6;
	int k7;
	int k8;
	int k9;
	int k10;
	int k11;
};

//auxiliary functions
int get64Bits(struct blockStruct* currentBlock, FILE* fp, int base);
uint16_t leftRotate(uint16_t* n, int steps , int size);
uint16_t rightRotate(uint16_t* n, int steps, int size);
uint64_t leftKeyRotate(uint64_t* n, int steps , int size);
uint64_t rightKeyRotate(uint64_t* n, int steps, int size);

//subroutines
int F(uint16_t r0, uint16_t r1, int round, int* f0, int* f1, uint64_t* key, int mode);
int G(int w, int k0, int k1, int k2, int k3);
int K(int x, uint64_t* key, int* mode);

int main(int argc, char* argv[]){
	//input checks
	if(argc != 4){	//too many arguments
		printf("Usage: ./wsu-crypt <text.txt> <key.txt> <encryption mode (e or d)\n");
		return 1;
	}

	//set encrypt/decrypt flag, exit otherwise
	int encFlag = 0;
	int decFlag = 0;
	if(strcmp(argv[3], "e") == 0){
		encFlag = 1;
	}
	else if(strcmp(argv[3], "d") == 0){
		decFlag = 1;
	}
	else{
		printf("Encryption mode: 'e' for encrypt, 'd' for decrypt.\n");
		return 1;
	}

	//see if result text files exist already (dependent on the mode)
	if(encFlag){	//check if ciphertext.txt already exists
		if(access("ciphertext.txt", F_OK) != -1){	//does, warn user
			printf("File 'ciphertext.txt' already exists in directory. Remove or move before running.\n");
			return 1;
		}
		else{	//reset errno
			errno = 0;
		}
	}
	else{	//check if plaintext.txt already exists
		if(access("plaintext.txt", F_OK) != -1){	//does, warn user
			printf("File 'plaintext.txt' already exists in directory. Remove or move before running.\n");
			return 1;
		}
		else{	//reset errno
			errno = 0;
		}
	}

	//start opening files
	FILE* mainText = fopen(argv[1], "r");	//plaintext/ciphertext, depending on mode
	if(mainText == NULL){
		fprintf(stderr, "Error opening file '%s': %s\n", argv[1], strerror(errno));
		exit(errno);
	}
	FILE* keyText = fopen(argv[2], "r");
	if(keyText == NULL){
		fprintf(stderr, "Error opening file '%s': %s\n", argv[2], strerror(errno));
		fclose(mainText);
		exit(errno);
	}
	FILE* resultText;
	if(encFlag){
		resultText = fopen("ciphertext.txt", "wb");
		if(resultText == NULL){
			fprintf(stderr, "Error creating file 'ciphertext.txt': %s\n", strerror(errno));
			fclose(mainText);
			fclose(keyText);
		}
	}
	else{
		resultText = fopen("plaintext.txt", "wb");
		if(resultText == NULL){
			fprintf(stderr, "Error creating file 'plaintext.txt': %s\n", strerror(errno));
			fclose(mainText);
			fclose(keyText);
		}
	}

	struct blockStruct* currentBlock;
	currentBlock = malloc(sizeof(struct blockStruct));
	if(currentBlock == NULL){
		fprintf(stderr, "Error during malloc: %s\n", strerror(errno));
		exit(errno);
	}
	struct blockStruct* keyBlock;
	keyBlock = malloc(sizeof(struct blockStruct));	//get key block
	if(keyBlock	== NULL){
		fprintf(stderr, "Error during malloc: %s\n", strerror(errno));
		exit(errno);
	}
	get64Bits(keyBlock, keyText, 16);	//obtain k0,k1,k2,k3 for whitening
	while(!feof(mainText)){	//while not eof
		//get block of bits
		if(encFlag){	//read ASCII
			if(get64Bits(currentBlock, mainText, 10)){
				break;
			}
		}
		else{	//read hex
			if(get64Bits(currentBlock, mainText, 16)){
				break;
			}
		}
		if(DEBUG){
			printf("Obtained info before whitening:\n");
			printf("Word1: %d\n", currentBlock->word1);
			printf("Word1 in Hex: %x\n", currentBlock->word1);
			printf("Word2: %d\n", currentBlock->word2);
			printf("Word3: %d\n", currentBlock->word3);
			printf("Word4: %d\n", currentBlock->word4);
			printf("Key1: %d\n", keyBlock->word1);
			printf("Key2: %d\n", keyBlock->word2);
			printf("Key3: %d\n", keyBlock->word3);
			printf("Key4: %d\n", keyBlock->word4);
		}
		//input whitening
		uint16_t r0 = currentBlock->word1 ^ keyBlock->word1;
		uint16_t r1 = currentBlock->word2 ^ keyBlock->word2;
		uint16_t r2 = currentBlock->word3 ^ keyBlock->word3;
		uint16_t r3 = currentBlock->word4 ^ keyBlock->word4;
		if(DEBUG){
			printf("CurrentBlock:%x %x %x %x\n", currentBlock->word1, currentBlock->word2, \
				currentBlock->word3, currentBlock->word4);
			printf("KeyBlock:%x %x %x %x\n", keyBlock->word1, keyBlock->word2, keyBlock->word3, keyBlock->word4);
			printf("Result from whitening:\n");
			printf("r0 %x, r1 %x, r2 %x, r3 %x\n", r0, r1, r2, r3);
		}
		int r0Old;
		int r1Old;
		uint64_t word1 = keyBlock->word1;
		uint64_t word2 = keyBlock->word2;
		uint64_t word3 = keyBlock->word3;
		uint64_t word4 = keyBlock->word4;
		uint64_t key = (word1 << 48)|(word2 << 32)|(word3 << 16)|word4;	//bit shift into single key
		if(DEBUG) printf("%lx\n", key);
		//rounds
		int round = 0;
		if(DEBUG) printf("----start of rounds----\n");
		while(round < 16){
			int f0, f1;
			if(DEBUG){
				printf("\tStart of round %d\n", round);
				printf("r0: %x, r1: %x\n", r0, r1);
			}

			F(r0, r1, round, &f0, &f1, &key, decFlag);
			
			r0Old = r0;
			r1Old = r1;
			if(encFlag){
				r0 = r2 ^ f0;
				r0 = rightRotate(&r0, 1, 16);
				r1 = leftRotate(&r3, 1, 16);
				r1 ^= f1;
			}
			else{
				r0 = leftRotate(&r2, 1, 16);
				r0 ^= f0;
				r1 = r3 ^ f1;
				r1 = rightRotate(&r1, 1, 16);
			}
			r2 = r0Old;
			r3 = r1Old;
			if(DEBUG){
				printf("r0:%x r1:%x r2:%x r3:%x\n", r0, r1, r2, r3);
				printf("\tEnd of round %d\n", round);
			}
			round++;
		}
		//-after rounds
		int y0 = r2, y1 = r3, y2 = r0, y3 = r1;
		//-output whitening
		currentBlock->word1 = y0 ^ keyBlock->word1;
		currentBlock->word2 = y1 ^ keyBlock->word2;
		currentBlock->word3 = y2 ^ keyBlock->word3;
		currentBlock->word4 = y3 ^ keyBlock->word4;
		if(DEBUG) printf("end hex: %x %x %x %x\n", currentBlock->word1, currentBlock->word2, \
			currentBlock->word3, currentBlock->word4);

		if(encFlag){
			printf("Outputting to ciphertext\n");
			fprintf(resultText, "%04x%04x%04x%04x", currentBlock->word1, currentBlock->word2, \
				currentBlock->word3, currentBlock->word4);
		}
		else{
			printf("Outputting to plaintext\n");
			fputc((currentBlock->word1 >> 8), resultText);
			fputc(currentBlock->word1, resultText);
			fputc((currentBlock->word2 >> 8), resultText);
			fputc(currentBlock->word2, resultText);
			fputc((currentBlock->word3 >> 8), resultText);
			fputc(currentBlock->word3, resultText);
			fputc((currentBlock->word4 >> 8), resultText);
			fputc(currentBlock->word4, resultText);
		}
	}
	printf("Finished converting text\n");
	free(currentBlock);
	free(keyBlock);
	fclose(mainText);
	fclose(keyText);
	fclose(resultText);
	return 0;
}

//auxiliary functions
//only supports decimal and hex
//horrific mess ahead
int get64Bits(struct blockStruct* currentBlock, FILE* fp, int base){
	if(base == 10){
		//int eofFlag = 0;
		for(int i = 0; i < 4; i++){
			int result;
			if(feof(fp)){	//end of file was set
				result = 0;	//zero padding
			}
			else{	//not end of file, more chars to be read
				int text1 = fgetc(fp);
				if(feof(fp)){	//end of file or error hit
					if(errno != 0){	//check if errno set
						fprintf(stderr, "Error during fgetc: %s\n", strerror(errno));
						exit(errno);
					}
					if(i == 0){	//empty at beginning
						return 1;
					}
					result = 0;	//zero padding
				}
				else{	//not end of file
					result = text1 << 8;	//bitshift char by 8
					int text2 = fgetc(fp);	//get text2
					if(feof(fp)){	//end of file or error hit
						if(errno != 0){	//check if errno set
							fprintf(stderr, "Error during fgetc: %s\n", strerror(errno));
							exit(errno);
						}
					}
					else{	//convert text2
						result ^= text2;	//bitwise XOR text2 into result
					}
				}
			}
			//insert result
			switch(i){
				case 0:
					currentBlock->word1 = result;
					break;
				case 1:
					currentBlock->word2 = result;
					break;
				case 2:
					currentBlock->word3 = result;
					break;
				case 3:
					currentBlock->word4 = result;
					break;
				default:	//should never occur
					printf("Something broke in the switch statement\n");
					break;
			}
		}
	}
	
	else if (base == 16){	//read 16 characters, otherwise tell user ciphertext is incorrect
		for(int i = 0; i < 4; i++){
			int result;
			if(feof(fp)){	//eof was hit
				result = 0;
			}
			else{
				char text1[3];
				if(fread(text1, 2, 1, fp)){	//read two bytes
					text1[3] = '\0';
					int hexDec1 = (int)strtol(text1, NULL, 16);	//convert to decimal
					if(errno != 0){	//doesn't handle characters not in base yet
						fprintf(stderr, "Error during strtol: %s\n", strerror(errno));
						exit(errno);
					}
					result = hexDec1 << 8;	//bitshift left by 8
				}
				else{	//error or eof
					if(errno != 0){	//error
						fprintf(stderr, "Error during fread: %s\n", strerror(errno));
						exit(errno);
					}
					else if(i == 0){	//eof at start
						return 1;
					}
					else{
						result = 0;
					}
				}
				char text2[3];
				if(fread(text2, 2, 1, fp)){
					text2[3] = '\0';
					int hexDec2 = (int)strtol(text2, NULL, 16);	//convert to decimal
					if(errno != 0){	//doesn't handle characters not in base yet
						fprintf(stderr, "Error during strtol: %s\n", strerror(errno));
						exit(errno);
					}
					result ^= hexDec2;	//bitwise XOR into result
				}
				else{	//error or eof
					if(errno != 0){	//error
						fprintf(stderr, "Error during fread: %s\n", strerror(errno));
						exit(errno);
					}
				}
			}
			//insert result
			switch(i){
				case 0:
					currentBlock->word1 = result;
					break;
				case 1:
					currentBlock->word2 = result;
					break;
				case 2:
					currentBlock->word3 = result;
					break;
				case 3:
					currentBlock->word4 = result;
					break;
				default:	//should never occur
					printf("Something broke in the switch statement\n");
					break;
			}
		}
	}
	else{	//shouldn't occur
		printf("Incorrect usage of get64Bits.\n");
		exit(1);
	}
	return 0;
}

//takes number n of size bits, rotates left by steps 
uint16_t leftRotate(uint16_t* n, int steps, int size){
	return (*n << steps)|(*n >> (size - steps));
}

//takes number n of size bits, rotates right by steps
uint16_t rightRotate(uint16_t* n, int steps, int size){
	return (*n >> steps)|(*n << (size - steps));
}

//takes number n of size bits, rotates left by steps 
uint64_t leftKeyRotate(uint64_t* n, int steps, int size){
	return (*n << steps)|(*n >> (size - steps));
}

//takes number n of size bits, rotates right by steps
uint64_t rightKeyRotate(uint64_t* n, int steps, int size){
	return (*n >> steps)|(*n << (size - steps));
}

//subfunctions
int F(uint16_t r0, uint16_t r1, int round, int* f0, int* f1, uint64_t* key, int decFlag){	//function F
	struct subkeyStruct* subkey;
	subkey = malloc(sizeof(struct subkeyStruct));
	if(subkey == NULL){
		fprintf(stderr, "Error during malloc: %s\n", strerror(errno));
		exit(errno);
	}
	if(decFlag == 0){	//encoding order
		subkey->k0 = K(4 * round, key, &decFlag);
		subkey->k1 = K((4 * round) + 1, key, &decFlag);
		subkey->k2 = K((4 * round) + 2, key, &decFlag);
		subkey->k3 = K((4 * round) + 3, key, &decFlag);
		subkey->k4 = K(4 * round, key, &decFlag);
		subkey->k5 = K((4 * round) + 1, key, &decFlag);
		subkey->k6 = K((4 * round) + 2, key, &decFlag);
		subkey->k7 = K((4 * round) + 3, key, &decFlag);
		subkey->k8 = K(4 * round, key, &decFlag);
		subkey->k9 = K((4 * round) + 1, key, &decFlag);
		subkey->k10 = K((4 * round) + 2, key, &decFlag);
		subkey->k11 = K((4 * round) + 3, key, &decFlag);
	}
	else{	//decoding order
		subkey->k11 = K(4 * round, key, &decFlag);
		subkey->k10 = K((4 * round) + 1, key, &decFlag);
		subkey->k9 = K((4 * round) + 2, key, &decFlag);
		subkey->k8 = K((4 * round) + 3, key, &decFlag);
		subkey->k7 = K(4 * round, key, &decFlag);
		subkey->k6 = K((4 * round) + 1, key, &decFlag);
		subkey->k5 = K((4 * round) + 2, key, &decFlag);
		subkey->k4 = K((4 * round) + 3, key, &decFlag);
		subkey->k3 = K(4 * round, key, &decFlag);
		subkey->k2 = K((4 * round) + 1, key, &decFlag);
		subkey->k1 = K((4 * round) + 2, key, &decFlag);
		subkey->k0 = K((4 * round) + 3, key, &decFlag);
	}
	if(DEBUG){
		printf("--subkeys--\n");
		printf("%x %x %x %x %x %x %x %x %x %x %x %x\n", subkey->k0, subkey->k1, subkey->k2, subkey->k3, \
			subkey->k4, subkey->k5, subkey->k6, subkey->k7, subkey->k8, subkey->k9, subkey->k10, subkey->k11);
	}
	int t0 = G(r0, subkey->k0, subkey->k1, subkey->k2, subkey->k3);
	int t1 = G(r1, subkey->k4, subkey->k5, subkey->k6, subkey->k7);
	int catk0 = ((subkey->k8) << 8)|(subkey->k9);
	long f0long = (t0 + (2 * t1) + catk0);	//(t0 + 2*t1 + concatenate(K(4*round), K(4*round+1))) mod 2^16 (which is 65536)
	*f0 = f0long % 65536;	//mod by 2^16 part
	int catk1 = ((subkey->k10) << 8)|(subkey->k11);
	long f1long = ((2* t0) + t1 + catk1);	//(2*t0 + t1 + concatenate(K(4*round+2), K(4*round+3))) mod 2^16
	*f1 = f1long % 65536;	//mod by 2^16 part
	if(DEBUG){
		printf("t0:%x t1:%x\n", t0, t1);
		printf("f0:%x f1:%x\n", *f0, *f1);
	}
	free(subkey);
	return 0;
}

int G(int w, int k0, int k1, int k2, int k3){	//G-Permutation
	//takes 16 bits as w, and round number 
	int ftable[] = {
		0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
		0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
		0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
		0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
		0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
		0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
		0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
		0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
		0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
		0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
		0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
		0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
		0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
		0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
		0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
		0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46};
	unsigned char g1, g2;
	g2 = w & 255;
	g1 = (w >> 8) & 255;
	int g3 = ftable[g2 ^ k0];
	g3 ^= g1;
	int g4 = ftable[g3 ^ k1];
	g4 ^= g2;
	int g5 = ftable[g4 ^ k2];
	g5 ^= g3;
	int g6 = ftable[g5 ^ k3];
	g6 ^= g4;
	int combine = (g5 << 8)|(g6);
	if(DEBUG) printf("g1:%x g2:%x g3:%x g4:%x g5:%x g6:%x\n", g1, g2, g3, g4, g5, g6);
	return combine;
}

int K(int x, uint64_t* key, int* mode){	//Key scheduler
	int wantedByte = x % 8;
	unsigned char subkey;
	uint64_t keyCopy;
	if(*mode == 0){	//encode mode
		*key = leftKeyRotate(key, 1, 64);
		keyCopy = *key;
		subkey = (keyCopy >> (wantedByte * 8)) & 255;
	}
	if(*mode == 1){	//decode mode
		keyCopy = *key;
		subkey = (keyCopy >> ((7 - wantedByte) * 8)) & 255;
		*key = rightKeyRotate(key, 1, 64);
	}
	return subkey;
}
