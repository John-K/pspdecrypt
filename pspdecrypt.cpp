#include <libgen.h>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <string>
#include <string.h>
#include <getopt.h>
#include "PsarDecrypter.h"
#include "PrxDecrypter.h"
#include "common.h"

using namespace std;
static const u32 ELF_MAGIC  = 0x464C457F;
static const u32 PSP_MAGIC  = 0x5053507E;
static const u32 PSAR_MAGIC = 0x52415350;
static const u32 PBP_MAGIC  = 0x50425000;

void help(const char* exeName) {
    cout << "Usage: " << exeName << " [OPTION]... [FILE]" << endl;
    cout << endl;
    cout << "Decrypts encrypted PSP binaries (.PSP) or updaters (.PSAR)." << endl;
    cout << "Can also take PBP files as an input, or IPL binaries if the option is given." << endl;
    cout << endl;
    cout << "General options:" << endl;
    cout << "  -v, --verbose      enable verbose mode (mostly for debugging)" << endl;
    cout << "PSP(/PBP)-only options:" << endl;
    cout << "  -o, --outfile      output file for the decrypted binary (default: [FILE.PSP].dec)" << endl;
    cout << "PSAR(/PBP)-only options:" << endl;
    cout << "  -e, --extract-only do not decrypt files contained in the PSAR" << endl;
    cout << "IPL decryption & PSAR(/PBP) options:" << endl;
    cout << "  -O, --outdir       output path for the PSAR's or IPL's contents (default: current directory)" << endl;
    cout << "  -i, --ipl-decrypt  decrypt the IPL given as an argument" << endl;
    cout << "  -p, --preipl       preipl image used for decrypting the later IPL stages" << endl;
}

int main(int argc, char *argv[]) {

    static struct option long_options[] = {
        {"help",         no_argument,       0, 'h'},
        {"verbose",      no_argument,       0, 'v'},
        {"outfile",      required_argument, 0, 'o'},
        {"extract-only", no_argument,       0, 'e'},
        {"outdir",       required_argument, 0, 'O'},
        {"ipl-decrypt",  no_argument,       0, 'i'},
        {"preipl",       required_argument, 0, 'p'},
        {0,              0,                 0,  0 }
    };
    int long_index;

    string inFilename = "";
    string outDir = ".";
    string outFile = "";
    string preipl = "";
    bool verbose = false;
    bool extractOnly = false;
    bool iplDecrypt = false;
    int c = 0;
    while ((c = getopt_long(argc, argv, "hvo:eO:ip:", long_options, &long_index)) != -1) {
        switch (c) {
            case 'h':
                help(argv[0]);
                return 0;
            case 'v':
                verbose = true;
                break;
            case 'o':
                outFile = string(optarg);
                break;
            case 'e':
                extractOnly = true;
                break;
            case 'O':
                outDir = string(optarg);
                break;
            case 'i':
                iplDecrypt = true;
                break;
            case 'p':
                preipl = string(optarg);
                break;
            default:
                help(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        cerr << "No file specified!" << endl;
        return 1;
    }

    if (optind + 1 < argc) {
        cerr << "More than two input files specified!" << endl;
        return 1;
    }

    inFilename = string(argv[optind]);

    if (outFile == "") {
        outFile = inFilename + ".dec";
    }

    ifstream inFile (inFilename, ios::in|ios::binary|ios::ate);
    if (!inFile.is_open()) {
        cerr << "Could not open " << inFilename << "!" << endl;
        return 1;
    }

    streampos size = inFile.tellg();
    char* inData = new char[size];
    char* outData = new char[size];
    inFile.seekg(0, ios::beg);
    inFile.read(inData, size);
    inFile.close();
    if (size < 0x30) {
        cerr << "Input file is too small!" << endl;
        return 1;
    }

    switch (*(u32*)inData) {
        case PSP_MAGIC:
            {
                int outSize = pspDecryptPRX((const u8*)inData, (u8 *)outData, size, nullptr, true);
                WriteFile(outFile.c_str(), outData, outSize);
            }
            break;
        case PBP_MAGIC:
            {
                u32 pspOff = *(u32*)&inData[0x20];
                u32 psarOff = *(u32*)&inData[0x24];
                if (pspOff < size) {
                    if (*(u32*)&inData[pspOff] == ELF_MAGIC) {
                        cout << "Non-encrypted PSP file, writing to " << outFile << endl;
                        WriteFile(outFile.c_str(), &inData[pspOff], psarOff - pspOff);
                    } else {
                        cout << "Decrypting PSP file to " << outFile << endl;
                        int outSize = pspDecryptPRX((const u8 *)&inData[pspOff], (u8 *)outData, psarOff - pspOff, nullptr, true);
                        WriteFile(outFile.c_str(), outData, outSize);
                    }
                }
                if (psarOff < size) {
                    cout << "Extracting PSAR to " << outDir << endl;
                    pspDecryptPSAR((u8*)&inData[psarOff], (u32)size - psarOff, outDir);
                }
            }
            break;
        case PSAR_MAGIC:
            pspDecryptPSAR((u8*)inData, size, outDir);
            break;
        case ELF_MAGIC:
            cout << "Non-encrypted file, copying to " << outFile << endl;
            WriteFile(outFile.c_str(), inData, size);
            break;
        default:
            cout << "Unknown input file format!" << endl;
            return 1;
    }

    return 0;
}
