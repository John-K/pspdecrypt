#include <libgen.h>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <string.h>
#include "PrxDecrypter.h"

using namespace std;

int
main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Usage: %s <infile>\n", basename(argv[0]));
		return 1;
	}
	char *outFilename = strdup(argv[1]);
	outFilename = strcat(outFilename, ".dec");

	ifstream inFile (argv[1], ios::in|ios::binary|ios::ate);
	if (!inFile.is_open()) {
		printf("Could not open '%s'\n", argv[1]);
		return 1;
	}

	streampos size = inFile.tellg();
	char* inData = new char[size];
	char* outData = new char[size];
	inFile.seekg(0, ios::beg);
	inFile.read(inData, size);
	inFile.close();

	//int pspDecryptPRX(const u8 *inbuf, u8 *outbuf, u32 size, const u8 *seed = nullptr);
	int outSize = pspDecryptPRX((const u8 *)inData, (u8 *)outData, size);
	printf("Decrypt returned %d\n", outSize);
	if (outSize > 0) {
		ofstream outFile;
		outFile.open(outFilename, ios::out | ios::app | ios::binary);
		if (!outFile.is_open()) {
			printf("Could not open '%s' for output\n", outFilename);
			return 1;
		}
		outFile.write(outData, outSize);
		outFile.close();
	}
	return 0;
}
