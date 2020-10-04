#include <libgen.h>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <string>
#include <string.h>
#include "PrxDecrypter.h"

using namespace std;
static const u32 ELF_SIGNATURE = 0x464C457F;
static const u32 PSP_SIGNATURE = 0x5053507E;
static const u32 PBP_SIGNATURE = 0x52415350;
static const u32 NUL_SIGNATURE = 0x00000000;

int
main(int argc, char *argv[]) {
	int outSize;

	if (argc != 2) {
		printf("Usage: %s <infile>\n", basename(argv[0]));
		return 1;
	}
	string filename = string(argv[1]) + ".dec";
	const char *outFilename = filename.c_str();

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

	// detect what type of file we're dealing with
	u32 file_signature = *(u32 *)inData;
	switch (file_signature) {
		case ELF_SIGNATURE:
			printf("File is already decrypted, exiting.\n");
			// let's write the file out as if it decrypted successfully to make things easier for folks
			outSize = size;
			break;
		case NUL_SIGNATURE:
			printf("Found NULL file signature - is the file empty?\n");
			return -1;
		case PSP_SIGNATURE:
			// let's decrypt!
			outSize = pspDecryptPRX((const u8 *)inData, (u8 *)outData, size);
			break;
		case PBP_SIGNATURE:
			printf("Found PBP, please run unpack-pbp. Exiting.\n");
			return -1;
		default:
			printf("Found unknown file signature 0x%08X, exiting.", file_signature);
			return -1;
	};

	if (outSize > 0) {
		ofstream outFile;
		outFile.open(outFilename, ios::out | ios::app | ios::binary);
		if (!outFile.is_open()) {
			printf("Could not open '%s' for output\n", outFilename);
			return 1;
		}
		outFile.write(outData, outSize);
		outFile.close();
		return 0;
	}
	return outSize;
}
