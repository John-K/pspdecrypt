#include <libgen.h>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <string>
#include <string.h>
#include "PsarDecrypter.h"

using namespace std;
static const u32 ELF_SIGNATURE = 0x464C457F;
static const u32 PSP_SIGNATURE = 0x5053507E;
static const u32 PBP_SIGNATURE = 0x52415350;

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
	char *inData = new char[size];
	inFile.seekg(0, ios::beg);
	inFile.read(inData, size);
	inFile.close();

	u32 psarOff = *(u32*)&inData[0x24];
	if (psarOff >= size) {
		printf("Wrong PSAR offset!?\n");
		return 1;
	}
	u8 *psarData = (u8*)&inData[psarOff];
	u32 psarSize = (u32)size - psarOff;
	pspDecryptPSAR(psarData, psarSize);

	delete[] inData;

    return 0;
}
