/*
 * Code taken in most part for the newpsardumper-660
 *
 * Original author: PspPet
 *
 * Contributions:
 * Vampire (bugfixes)
 * Nem (ipl decryption)
 * Dark_AleX (2.60-2.80 decryption)
 * Noobz (3.00-3.02 decryption)
 * Team C+D (3.03-3.52 decryption)
 * M33 Team (3.60-3.71 decryption) + recode for 2.XX+ kernels 
 * bbtgp (6.00-6.20 decryption)
 * Proxima, some1 (6.60 version)
 *
 * This code was adapted for usage on PC with minor additions and fixes
 * (ME image decryption, buggy decryption for older firmwares, etc.)
 */

#include <algorithm>
#include <array>
#include <string.h>
#include <cstdio>
#include <zlib.h>
#include <sys/stat.h>
#include <fstream>
#include <array>
#include <vector>
#include <iostream>

extern "C"
{
#include "libkirk/kirk_engine.h"
#include "libkirk/SHA1.h"
}
#include "PsarDecrypter.h"
#include "pspdecrypt_lib.h"
#include "PrxDecrypter.h"
#include "common.h"
#include "ipl_decrypt.h"

#define DATA_SIZE 3000000

static int OVERHEAD;
#define SIZE_A      0x110 /* size of uncompressed file entry = 272 bytes */

int iBase, cbChunk, psarVersion;
int decrypted;

// File tables, com = offset 0, then 01g = offset 1, etc.
std::array<std::vector<char>, 13> g_tables;

const std::vector<std::pair<std::string, int>> g_tableFilenames = {
    {"com:00000", 0},
    {"01g:00000", 1},
    {"02g:00000", 2},
    {"00001", 1},
    {"00002", 2},
    {"00003", 3},
    {"00004", 4},
    {"00005", 5},
    {"00006", 6},
    {"00007", 7},
    {"00008", 8},
    {"00009", 9},
    {"00011", 11},
    {"00012", 12}
};

static int FindTablePath(const char *table, int table_size, char *number, char *szOut)
{
    int i, j, k;

    for (i = 0; i < table_size-5; i++)
    {
        if (strncmp(number, table+i, 5) == 0)
        {
            for (j = 0, k = 0; ; j++, k++)
            {
                if (table[i+j+6] < 0x20)
                {
                    szOut[k] = 0;
                    break;
                }

                if (table[i+5] == '|' && !strncmp(table+i+6, "flash", 5) &&
                    j == 6)
                {
                    szOut[6] = ':';
                    szOut[7] = '/';
                    k++;
                }
                else if (table[i+5] == '|' && !strncmp(table+i+6, "ipl", 3) &&
                    j == 3)
                {
                    szOut[3] = ':';
                    szOut[4] = '/';
                    k++;
                }
                else
                {
                    szOut[k] = table[i+j+6];
                }
            }

            return 1;
        }
    }

    return 0;
}

static int FindReboot(u8 *input, u8 *output, int size)
{
    int i;

    for (i = 0; i < (size - 0x30); i++)
    {
        if (memcmp(input+i, "~PSP", 4) == 0)
        {
            size = *(u32 *)&input[i+0x2C];

            memcpy(output, input+i, size);
            return size;
        }
    }

    return -1;
}

static int ExtractReboot(u8 *loadexec_data, int loadexec_data_size, const char *reboot, const char *rebootname, u8 *data1, u8 *data2, bool extractOnly, std::string &logStr)
{
    int s = loadexec_data_size;
    memcpy(data1, loadexec_data, loadexec_data_size);

    if (s <= 0) {
        return -1;
    }

    logStr += " Extracting " + std::string(rebootname);

    s = FindReboot(data1, data2, s);
    if (s <= 0)
    {
        printf("Cannot find %s inside loadexec.\n", rebootname);
        return -1;
    }

    if (extractOnly) {
        if (WriteFile(reboot, data2, s) != s) {
            printf("Cannot write %s.\n", reboot);
            return -1;
        }
        logStr += ",saved!";
        return 0;
    }

    s = pspDecryptPRX(data2, data1, s);
    if (s <= 0)
    {
        printf("Cannot decrypt %s.\n", rebootname);
        return -1;
    }
    logStr += ",decrypted";

    WriteFile(reboot, data1, s);

    s = pspDecompress(data1, DATA_SIZE, data2, DATA_SIZE, logStr);
    if (s <= 0)
    {
        printf("Cannot decompress %s (0x%08X).\n", rebootname, s);
        return -1;
    }

    if (WriteFile(reboot, data2, s) != s)
    {
        printf("Cannot write %s.\n", reboot);
        return -1;
    }

    logStr += ",done.";
    return 0;
}

static int CheckExtractReboot(const char *name, u8 *pbToSave, int cbToSave, u8 *data1, u8 *data2, std::string outdir, bool extractOnly, std::string &logStr) {
    if (strcmp(name, "flash0:/kd/loadexec.prx") == 0) {
        return ExtractReboot(pbToSave, cbToSave, (outdir + "/PSARDUMPER/reboot.bin").c_str(), "reboot.bin", data1, data2, extractOnly, logStr);
    } else if (strncmp(name, "flash0:/kd/loadexec_", strlen("flash0:/kd/loadexec_")) == 0) {
        if (strlen(name) == strlen("flash0:/kd/loadexec_00g.prx")) {
            std::string filename = "reboot_00g.bin";
            filename[strlen("reboot_")] = name[strlen("flash0:/kd/loadexec_")];
            filename[strlen("reboot_") + 1] = name[strlen("flash0:/kd/loadexec_") + 1];
            return ExtractReboot(pbToSave, cbToSave, (outdir + "/PSARDUMPER/" + filename).c_str(), filename.c_str(), data1, data2, extractOnly, logStr);
        }
        return -1;
    }
    return 0;
}

// for 1.50 and later, they mangled the plaintext parts of the header
static void Demangle(const u8* pIn, u8* pOut)
{
    u8 buffer[20+0x130];
    u8 K1[0x10] = { 0xD8, 0x69, 0xB8, 0x95, 0x33, 0x6B, 0x63, 0x34, 0x98, 0xB9, 0xFC, 0x3C, 0xB7, 0x26, 0x2B, 0xD7 };
    u8 K2[0x10] = { 0x0D, 0xA0, 0x90, 0x84, 0xAF, 0x9E, 0xB6, 0xE2, 0xD2, 0x94, 0xF2, 0xAA, 0xEF, 0x99, 0x68, 0x71 };
    int i;
    memcpy(buffer+20, pIn, 0x130);
    if (psarVersion == 5) for ( i = 0; i < 0x130; ++i ) { buffer[20+i] ^= K1[i & 0xF]; }
    u32* pl = (u32*)buffer; // first 20 bytes
    pl[0] = 5;
    pl[1] = pl[2] = 0;
    pl[3] = 0x55;
    pl[4] = 0x130;

    sceUtilsBufferCopyWithRange(buffer, 20+0x130, buffer, 20+0x130, 0x7);
    if (psarVersion == 5) for ( i = 0; i < 0x130; ++i ) { buffer[i] ^= K2[i & 0xF]; }
    memcpy(pOut, buffer, 0x130);
}

static int DecodeBlock(const u8* pIn, int cbIn, u8* pOut)
{
    // pOut also used as temporary buffer for mangled input
    // assert((((u32)pOut) & 0x3F) == 0); // must be aligned

    if (decrypted)
    {
        if (pIn != pOut)
        {
            memcpy(pOut, pIn, cbIn);
        }

        return cbIn;
    }

    memcpy(pOut, pIn, cbIn + 0x10); // copy a little more for $10 page alignment

    int ret;
    int cbOut;

    if (psarVersion != 1)
    {
        Demangle(pIn+0x20, pOut+0x20); // demangle the inside $130 bytes
    }

    cbOut = pspDecryptPRX(pOut, pOut, cbIn);
    if (cbOut < 0)
    {
        //printf("Unknown psar tag.\n");
        return 0xFFFFFFFC;
    }
    return cbOut;
}

int pspPSARInit(const u8 *dataPSAR, u8 *dataOut, u8 *dataOut2)
{
    if (memcmp(dataPSAR, "PSAR", 4) != 0)
    {
        return -1;
    }

    decrypted = (*(u32 *)&dataPSAR[0x20] == 0x2C333333); // 3.5X M33, and 3.60 unofficial psar's

    if (decrypted)
    {
        OVERHEAD = 0;
    }
    else
    {
        OVERHEAD = 0x150;
    }

    //oldschool = (dataPSAR[4] == 1); /* bogus update */
    psarVersion = dataPSAR[4];

    int cbOut;

    // at the start of the PSAR file,
    //   there are one or two special version data chunks
    // printf("Special PSAR records:\n");
    cbOut = DecodeBlock(&dataPSAR[0x10], OVERHEAD+SIZE_A, dataOut);
    if (cbOut <= 0)
    {
        return cbOut;
    }

    if (cbOut != SIZE_A)
    {
        return -2;
    }

    iBase = 0x10+OVERHEAD+SIZE_A; // after first entry
            // iBase points to the next block to decode (0x10 aligned)

    if (decrypted)
    {
        cbOut = DecodeBlock(&dataPSAR[0x10+OVERHEAD+SIZE_A], *(u32 *)&dataOut[0x90], dataOut2);
        if (cbOut <= 0)
        {
            return -3;
        }

        iBase += OVERHEAD+cbOut;
        return 0;
    }

    if (psarVersion != 1)
    {
        // second block
        cbOut = DecodeBlock(&dataPSAR[0x10+OVERHEAD+SIZE_A], OVERHEAD+100, dataOut2);
        if (cbOut <= 0)
        {
            //printf("Performing V2.70 test\n"); // version 2.7 is bigger
            cbOut = DecodeBlock(&dataPSAR[0x10+OVERHEAD+SIZE_A], OVERHEAD+144, dataOut2);
            if (cbOut <= 0)
            {
                cbOut = DecodeBlock(&dataPSAR[0x10+OVERHEAD+SIZE_A], OVERHEAD+*(u16 *)&dataOut[0x90], dataOut2);
                if (cbOut <= 0)
                {
                    return -4;
                }
            }
        }

        cbChunk = (cbOut + 15) & 0xFFFFFFF0;
        iBase += OVERHEAD+cbChunk;
    }

    return 0;
}

int pspPSARGetNextFile(u8 *dataPSAR, int cbFile, u8 *dataOut, u8 *dataOut2, char *name, int *retSize, int *retPos, int *signcheck)
{
    int cbOut;

    if (iBase >= (cbFile-OVERHEAD))
    {
        return 0; // no more files
    }

    cbOut = DecodeBlock(&dataPSAR[iBase], OVERHEAD+SIZE_A, dataOut);

    if (cbOut <= 0)
    {
        return -1;
    }
    if (cbOut != SIZE_A)
    {
        return -1;
    }

    strcpy(name, (const char*)&dataOut[4]);
    u32* pl = (u32*)&dataOut[0x100];
    *signcheck = (dataOut[0x10F] == 2);

    // pl[0] is 0
    // pl[1] is the PSAR chunk size (including OVERHEAD)
    // pl[2] is true file size (TypeA=272=SIZE_A, TypeB=size when expanded)
    // pl[3] is flags or version?
    if (pl[0] != 0)
    {
        return -1;
    }

    iBase += OVERHEAD + SIZE_A;
    u32 cbDataChunk = pl[1]; // size of next data chunk (including OVERHEAD)
    u32 cbExpanded = pl[2]; // size of file when expanded
    if (cbExpanded > 0)
    {
        cbOut = DecodeBlock(&dataPSAR[iBase], cbDataChunk, dataOut);
        if (cbOut > 10 && dataOut[0] == 0x78 && dataOut[1] == 0x9C)
        {
            int ret = gunzip(dataOut, cbOut, dataOut2, cbExpanded, NULL, true);
            if (ret == cbExpanded)
            {
                *retSize = ret;
            }

            else
            {
                return -1;
            }
        }

        else
        {
            iBase -= (OVERHEAD + SIZE_A);
            return -1;
        }
    }

    else if (cbExpanded == 0)
    {
        *retSize = 0;
        // Directory    
    }

    else
    {
        return -1;
    }

    iBase += cbDataChunk;
    *retPos = iBase;

    return 1; // morefiles
}

static const char *GetVersion(char *buf)
{
    char *p = strrchr(buf, ',');

    if (!p)
        return "1.00";

    return p+1;
}

static int is5Dnum(char *str)
{
    int len = strlen(str);

    if (len != 5)
        return 0;

    int i;

    for (i = 0; i < len; i++)
    {
        if (str[i] < '0' || str[i] > '9')
            return 0;
    }

    return 1;
}

#ifdef _WIN32
	#define mkdir(a,b) mkdir(a)
#endif

void makeDirs(std::string filename, bool isDir)
{
    for (size_t i = 0; i < filename.size(); i++) {
        if (filename[i] == '/') {
            filename[i] = '\0';
            mkdir(filename.c_str(), 0777);
            filename[i] = '/';
        }
    }
    if (isDir) {
        mkdir(filename.c_str(), 0777);
    }
}

int pspDecryptPSAR(u8 *dataPSAR, u32 size, std::string outdir, bool extractOnly, u8 *preipl, u32 preiplSize, bool verbose, bool infoOnly, bool keepAll, bool decompPsp)
{
    kirk_init();
    if (memcmp(dataPSAR, "PSAR", 4) != 0) {
        printf("Invalid PSAR magic\n");
        return 1;
    }
    u8 *data1 = new u8[DATA_SIZE];
    u8 *data2 = new u8[DATA_SIZE];
    printf("PSAR version %d\n", dataPSAR[4]);
    int res = pspPSARInit(dataPSAR, data1, data2);
    if (res < 0)
    {
        printf("pspPSARInit failed with error 0x%08X!.\n", res);
    }

    char version[10];
    strncpy(version, GetVersion((char *)data1+0x10), 10);
    version[9] = '\0';
    printf("Firmware version %s.\n", version);
    if (version[1] != '.' || strlen(version) != 4) {
        printf("Invalid version!?\n");
        return 1;
    }
    int intVersion = (version[0] - '0') * 100 + (version[2] - '0') * 10 + version[3] - '0';
    int table_mode;

    if (intVersion >= 380 && intVersion < 400) {
        table_mode = 1;
    } else if (intVersion >= 400 && intVersion < 500) {
        table_mode = 2;
    } else if (intVersion >= 500 && intVersion < 600) {
        table_mode = 3;
    } else if (intVersion >= 610 && intVersion < 630 && psarVersion == 5) {
        table_mode = 5;
    } else if (intVersion >= 600 && intVersion < 700) {
        table_mode = 4;
    } else {
        table_mode = 0;
    }

    printf("table_mode = %d\n", table_mode);
    if (infoOnly) {
        return 0;
    }

    mkdir((outdir).c_str(), 0777);
    mkdir((outdir + "/F0").c_str(), 0777);
    mkdir((outdir + "/F1").c_str(), 0777);
    mkdir((outdir + "/PSARDUMPER").c_str(), 0777);

    while (1)
    {
        std::string logStr;
        char name[128];
        int cbExpanded;
        int pos;
        int signcheck;

        int res = pspPSARGetNextFile(dataPSAR, size, data1, data2, name, &cbExpanded, &pos, &signcheck);
        if (res < 0) {
            printf("Error when decrypting PSAR block!\n");
            return 1;
        }

        if (res == 0) /* no more files */
        {
            break;
        }

        if (is5Dnum(name))
        {
            if (atoi(name) >= 100 || (atoi(name) >= 10 && intVersion < 660))
            {
                int found = 0;
                for (const auto &table : g_tables) {
                    if (table.size() > 0) {
                        found = FindTablePath(table.data(), table.size(), name, name);
                        if (found) {
                            break;
                        }
                    }
                }

                if (!found)
                {
                    printf("Part 1 Error: cannot find path of %s.\n", name);
                    continue;
                }
            }
        }

        else if (!strncmp(name, "com:", 4) && g_tables[0].size() > 0)
        {
            if (!FindTablePath(g_tables[0].data(), g_tables[0].size(), name+4, name))
            {
                printf("Part 2 Error: cannot find path of %s.\n", name);
                continue;
            }
        }

        else if (!strncmp(name, "01g:", 4) && g_tables[1].size() > 0)
        {
            if (!FindTablePath(g_tables[1].data(), g_tables[1].size(), name+4, name))
            {
                printf("Error: 01g cannot find path of %s.\n", name);
                continue;
            }
        }

        else if (!strncmp(name, "02g:", 4) && g_tables[2].size() > 0)
        {
            if (!FindTablePath(g_tables[2].data(), g_tables[2].size(), name+4, name))
            {
                printf("Error: 02g cannot find path of %s.\n", name);
                continue;
            }
        }

        logStr = "'" + std::string(name) + "' ";

        const char* szFileBase = strrchr(name, '/');

        if (szFileBase != NULL)
            szFileBase++;  // after slash
        else
            szFileBase = "err.err";

        std::string szDataPath;
        int found = 0;

        if (!strncmp(name, "flash0:/", 8)) {
            szDataPath = outdir + "/F0/" + (name + 8);
            makeDirs(szDataPath, cbExpanded == 0);
            found = 1;
        } else if (!strncmp(name, "flash1:/", 8)) {
            szDataPath = outdir + "/F1/" + (name + 8);
            makeDirs(szDataPath, cbExpanded == 0);
            found = 1;
        } else {
            for (auto &tableName : g_tableFilenames) {
                if (!strncmp(name, tableName.first.data(), tableName.first.size())) {
                    int size = pspDecryptTable(data2, data1, cbExpanded, psarVersion, table_mode);
                    g_tables[tableName.second].resize(size);
                    memcpy(g_tables[tableName.second].data(), data2, size);
                    szDataPath = outdir + "/PSARDUMPER/";
                    if (tableName.second == 0) {
                        szDataPath += "common";
                    } else {
                        char modelNum[6];
                        sprintf(modelNum, "%05d", tableName.second);
                        szDataPath += std::string(modelNum);
                    }
                    szDataPath += "_files_table.bin";
                    found = 1;
                    break;
                }
            }
        }
        if (!found) {
            szDataPath = outdir + "/PSARDUMPER/" + (strrchr(name, '/') + 1);
        }

        if (cbExpanded > 0)
        {
            logStr += "expanded";

            // If we don't decrypt modules, or for non-encrypted modules
            if (extractOnly || (memcmp(data2, "~PSP", 4) != 0))
            {
                // Check if the IPL file is not a kirk1 (or kirk1 with additional keys for 03g+), which means it needs predecryption
                if (!extractOnly && strncmp(name, "ipl:", 4) == 0
                    && *(u32*)(data2 + 0x60) != 1 && *(u32*)(data2 + 0x60) != 0x10001)
                {
                    // IPL Pre-decryption
                    cbExpanded = pspDecryptPRX(data2, data1, cbExpanded);

                    if (cbExpanded <= 0)
                    {
                        logStr += ",pre-decrypt failed";
                    }
                    else
                    {
                        logStr += ",pre-decrypt ok";
                        memcpy(data2, data1, cbExpanded);
                    }
                }

                if (WriteFile(szDataPath.c_str(), data2, cbExpanded) != cbExpanded)
                {
                    printf("Cannot write %s.\n", szDataPath.c_str());
                    break;
                }

                logStr += ",saved!";
                if (CheckExtractReboot(name, data2, cbExpanded, data1, data2, outdir, extractOnly, logStr) < 0) {
                    logStr += ",error extracting/decrypting reboot.bin";
                }
            }

            // For encrypted ~PSP modules, or ME images, if decrypting is not disabled
            if ((memcmp(data2, "~PSP", 4) == 0 || strncmp(name, "flash0:/kd/resource/me", strlen("flash0:/kd/resource/me")) == 0) &&
                !extractOnly)
            {
                int cbDecrypted = pspDecryptPRX(data2, data1, cbExpanded);

                // output goes back to main buffer
                // trashed 'data2'
                if (cbDecrypted > 0)
                {
                    u8* pbToSave = data1;
                    int cbToSave = cbDecrypted;

                    logStr += ",decrypted";
                    u8 *endPtr;
                    int cbRemain = 0;

                    if (pspIsCompressed(data1))
                    {
                        if (decompPsp) {
                            int cbExp = pspDecompress(data1, cbToSave, data2, 3000000, logStr, &endPtr);
                            cbRemain = data1 + cbToSave - endPtr;

                            if (cbExp > 0)
                            {
                                logStr += ",decompressed";
                                pbToSave = data2;
                                cbToSave = cbExp;
                            }
                            else
                            {
                                logStr += ",error decompressing";
                            }
                        }
                        else {
                            logStr += ",skipped decompression";
                        }
                    }

                    if (WriteFile(szDataPath.c_str(), pbToSave, cbToSave) != cbToSave)
                    {
                        printf("Error writing %s.\n", szDataPath.c_str());
                    }

                    logStr += ",saved!";
                    if (CheckExtractReboot(name, pbToSave, cbToSave, data1, data2, outdir, extractOnly, logStr) < 0) {
                        logStr += ",error extracting/decrypting reboot.bin";
                    }

                    if (cbRemain > 0) {
                        u8 *endPtr2;
                        logStr += "Has part2";
                        int cbExp = pspDecompress(endPtr, cbRemain, data2, 3000000, logStr, &endPtr2);
                        if (cbExp > 0) {
                            logStr += ",decompressed,saved!";
                            if (endPtr + cbRemain - endPtr2 != 0) {
                                logStr += "Error: garbage at end.";
                            }
                            if (WriteFile((szDataPath + ".2").c_str(), data2, cbExp) != cbExp)
                            {
                                printf("Error writing %s.\n", (szDataPath + ".2").c_str());
                            }
                        } else {
                            logStr += ",error decompressing!";
                        }
                    }
                }
                else
                {
                    char tagStr[9];
                    snprintf(tagStr, sizeof(tagStr), "%08x", pspGetTagVal(data2));
                    logStr += std::string(",error during decryption [tag ") + tagStr + "].";
                }
            }

            else if (strncmp(name, "ipl:", 4) == 0 && !extractOnly)
            {
                decryptIPL(data2, cbExpanded, intVersion, szFileBase, outdir + "/PSARDUMPER", preipl, preiplSize, verbose, keepAll, logStr);
            }
        }
        else
        {
            logStr += "empty";
        }

        std::cout << logStr << std::endl;
    }
    printf("Done!\n");

    return 0;
}
