#include <libgen.h>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <string>
#include <string.h>
#include "PsarDecrypter.h"

using namespace std;

int
main(int argc, char *argv[]) {
	int outSize;

	if (argc != 3 && argc != 2) {
		printf("Usage: %s <infile> [outdir] \n", basename(argv[0]));
		return 1;
	}
	string filename = string(argv[1]) + ".dec";
	string outdir;
	
	if(argc == 3) {
		outdir = string(argv[2]);
	}
	else if (argc == 2){
		outdir = string("./");
	}
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

	if (*(u32*)inData == 0x52415350) {
	    pspDecryptPSAR((u8*)inData, size, outdir);
	} else {
	    if (size < 0x38 || *(u32*)inData != 0x50425000) {
	        printf("Input must be an updater .PBP or a .PSAR file.\n");
	        return 1;
	    }

	    u32 psarOff = *(u32*)&inData[0x24];
	    if (psarOff >= size) {
		    printf("Wrong PSAR offset!?\n");
		    return 1;
	    }
	    u8 *psarData = (u8*)&inData[psarOff];
	    u32 psarSize = (u32)size - psarOff;
	    pspDecryptPSAR(psarData, psarSize, outdir);
	}

	delete[] inData;

    return 0;
}
