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

#define LOADER "LOADER"
#define INFO_LOG(type, fmt, ...) printf(type ": " fmt "\n", __VA_ARGS__)
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

enum
{
    MODE_ENCRYPT_SIGCHECK,
    MODE_ENCRYPT,
    MODE_DECRYPT,
};

int mode = MODE_DECRYPT;

static char com_table[0x4000];
static int comtable_size;

static char _1g_table[0x4000];
static int _1gtable_size;

static char _2g_table[0x4000];
static int _2gtable_size;

static char _3g_table[0x4000];
static int _3gtable_size;

static char _4g_table[0x4000];
static int _4gtable_size;

static char _5g_table[0x4000];
static int _5gtable_size;

static char _6g_table[0x4000];
static int _6gtable_size;

static char _7g_table[0x4000];
static int _7gtable_size;

static char _8g_table[0x4000];
static int _8gtable_size;

static char _9g_table[0x4000];
static int _9gtable_size;

static char _10g_table[0x4000];
static int _10gtable_size;

static char _11g_table[0x4000];
static int _11gtable_size;

static char _12g_table[0x4000];
static int _12gtable_size;

static int FindTablePath(char *table, int table_size, char *number, char *szOut)
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

static void ExtractReboot(int mode, u8 *loadexec_data, int loadexec_data_size, const char *reboot, const char *rebootname, u8 *data1, u8 *data2)
{
    int s = loadexec_data_size;
    memcpy(data1, loadexec_data, loadexec_data_size);

    if (s <= 0)
        return;

    printf(",extracting %s", rebootname);

    s = FindReboot(data1, data2, s);
    if (s <= 0)
    {
        printf("Cannot find %s inside loadexec.\n", rebootname);
        return;
    }

    s = pspDecryptPRX(data2, data1, s);
    if (s <= 0)
    {
        printf("Cannot decrypt %s.\n", rebootname);
        return;
    }

    WriteFile(reboot, data1, s);

    s = pspDecompress(data1, DATA_SIZE, data2, DATA_SIZE);
    if (s <= 0)
    {
        printf("Cannot decompress %s (0x%08X).\n", rebootname, s);
        return;
    }

    if (WriteFile(reboot, data2, s) != s)
    {
        printf("Cannot write %s.\n", reboot);
        return;
    }

    printf(",done.");
}

static void CheckExtractReboot(const char *name, int mode, u8 *pbToSave, int cbToSave, u8 *data1, u8 *data2, std::string outdir) {
    if (strcmp(name, "flash0:/kd/loadexec.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot.bin").c_str(), "reboot.bin", data1, data2);
    }
    if (strcmp(name, "flash0:/kd/loadexec_01g.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot_01g.bin").c_str(), "reboot_01g.bin", data1, data2);
    }
    if (strcmp(name, "flash0:/kd/loadexec_02g.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot_02g.bin").c_str(), "reboot_02g.bin", data1, data2);
    }
    if (strcmp(name, "flash0:/kd/loadexec_03g.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot_03g.bin").c_str(), "reboot_03g.bin", data1, data2);
    }
    if (strcmp(name, "flash0:/kd/loadexec_04g.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot_04g.bin").c_str(), "reboot_04g.bin", data1, data2);
    }
    if (strcmp(name, "flash0:/kd/loadexec_05g.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot_05g.bin").c_str(), "reboot_05g.bin", data1, data2);
    }
    if (strcmp(name, "flash0:/kd/loadexec_06g.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot_06g.bin").c_str(), "reboot_06g.bin", data1, data2);
    }
    if (strcmp(name, "flash0:/kd/loadexec_07g.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot_07g.bin").c_str(), "reboot_07g.bin", data1, data2);
    }
    if (strcmp(name, "flash0:/kd/loadexec_08g.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot_08g.bin").c_str(), "reboot_08g.bin", data1, data2);
    }
    if (strcmp(name, "flash0:/kd/loadexec_09g.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot_09g.bin").c_str(), "reboot_09g.bin", data1, data2);
    }
    if (strcmp(name, "flash0:/kd/loadexec_10g.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot_10g.bin").c_str(), "reboot_10g.bin", data1, data2);
    }
    if (strcmp(name, "flash0:/kd/loadexec_11g.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot_11g.bin").c_str(), "reboot_11g.bin", data1, data2);
    }
    if (strcmp(name, "flash0:/kd/loadexec_12g.prx") == 0) {
        ExtractReboot(mode, pbToSave, cbToSave, (outdir + "/F0/PSARDUMPER/reboot_12g.bin").c_str(), "reboot_12g.bin", data1, data2);
    }
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
    printf("psarVersion = %d\n", dataPSAR[4]);

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
            // standard Deflate header

            u8* pbIn = &dataOut[0]; // after header
            u32 pbEnd;
            z_stream infstream;
            infstream.zalloc = Z_NULL;
            infstream.zfree = Z_NULL;
            infstream.opaque = Z_NULL;
            // setup "b" as the input and "c" as the compressed output
            infstream.avail_in = cbOut; // size of input
            infstream.next_in = pbIn; // input
            infstream.avail_out = cbExpanded; // size of output
            infstream.next_out = dataOut2; // output char array
              
            // the actual DE-compression work.
            inflateInit(&infstream);
            int x = inflate(&infstream, Z_NO_FLUSH);
            inflateEnd(&infstream);

            //int ret = sceKernelDeflateDecompress(dataOut2, cbExpanded, pbIn, &pbEnd);
            int ret = infstream.total_out;
            if (ret == cbExpanded)
            {
                *retSize = ret;
            }

            else
            {
                //return -1;
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

#define PSAR_BUFFER_SIZE    9400000

int pspDecryptPSAR(u8 *dataPSAR, u32 size, std::string outdir)
{
    kirk_init();
    if (memcmp(dataPSAR, "PSAR", 4) != 0) {
        printf("Invalid PSAR magic\n");
        return 1;
    }
    u8 *data1 = new u8[DATA_SIZE];
    u8 *data2 = new u8[DATA_SIZE];
    printf("PSAR ok version %d\n", dataPSAR[4]);
    int res = pspPSARInit(dataPSAR, data1, data2);
    if (res < 0)
    {
        printf("pspPSARInit failed with error 0x%08X!.\n", res);
    }

    char version[10];
    strncpy(version, GetVersion((char *)data1+0x10), 10);
    version[9] = '\0';
    printf("Version %s.\n", version);
    if (version[1] != '.' || strlen(version) != 4) {
        printf("Invalid version!?\n");
        return 1;
    }
    int intVersion = (version[0] - '0') * 100 + (version[2] - '0') * 10 + version[3] - '0';
    int table_mode;

    if (memcmp(version, "3.8", 3) == 0 || memcmp(version, "3.9", 3) == 0)
    {
        table_mode = 1;
    }
    else if (memcmp(version, "4.", 2) == 0)
    {
        table_mode = 2;
    }
    else if (memcmp(version, "5.", 2) == 0)
    {
        table_mode = 3;
    }
    else if ((memcmp(version, "6.3", 3) == 0) && (psarVersion == 5))
    {
        table_mode = 4;
    }
    else if ((memcmp(version, "6.", 2) == 0) && (psarVersion == 5))
    {
        table_mode = 4;
    }
    else if (memcmp(version, "6.", 2) == 0)
    {
        table_mode = 4;
    }
    else
    {
        table_mode = 0;
    }

#ifdef _WIN32
	#define mkdir(a,b) mkdir(a)
#endif

    mkdir((outdir).c_str(), 0777);
    mkdir((outdir + "/F0").c_str(), 0777);
    mkdir((outdir + "/F0/PSARDUMPER").c_str(), 0777);
    mkdir((outdir + "/F0/data").c_str(), 0777);
    mkdir((outdir + "/F0/dic").c_str(), 0777);
    mkdir((outdir + "/F0/font").c_str(), 0777);
    mkdir((outdir + "/F0/kd").c_str(), 0777);
    mkdir((outdir + "/F0/vsh").c_str(), 0777);
    mkdir((outdir + "/F0/data/cert").c_str(), 0777);
    mkdir((outdir + "/F0/kd/resource").c_str(), 0777);
    mkdir((outdir + "/F0/vsh/etc").c_str(), 0777);
    mkdir((outdir + "/F0/vsh/module").c_str(), 0777);
    mkdir((outdir + "/F0/vsh/resource").c_str(), 0777);
    mkdir((outdir + "/F0/codepage").c_str(), 0777);

    printf("table_mode = %d\n", table_mode);

    while (1)
    {
        char name[128];
        int cbExpanded;
        int pos;
        int signcheck;

        int res = pspPSARGetNextFile(dataPSAR, size, data1, data2, name, &cbExpanded, &pos, &signcheck);

        if (res == 0) /* no more files */
        {
            break;
        }

        if (is5Dnum(name))
        {
            if (atoi(name) >= 100 || (atoi(name) >= 10 && memcmp(version, "6.6", 3) != 0))
            {
                int found = 0;

                if (_1gtable_size > 0)
                {
                    found = FindTablePath(_1g_table, _1gtable_size, name, name);
                }

                if (!found && _2gtable_size > 0)
                {
                    found = FindTablePath(_2g_table, _2gtable_size, name, name);
                }

                if (!found && _3gtable_size > 0)
                {
                    found = FindTablePath(_3g_table, _3gtable_size, name, name);
                }

                if (!found && _4gtable_size > 0)
                {
                    found = FindTablePath(_4g_table, _4gtable_size, name, name);
                }

                if (!found && _5gtable_size > 0)
                {
                    found = FindTablePath(_5g_table, _5gtable_size, name, name);
                }

                if (!found && _6gtable_size > 0)
                {
                    found = FindTablePath(_6g_table, _6gtable_size, name, name);
                }

                if (!found && _7gtable_size > 0)
                {
                    found = FindTablePath(_7g_table, _7gtable_size, name, name);
                }

                if (!found && _8gtable_size > 0)
                {
                    found = FindTablePath(_8g_table, _8gtable_size, name, name);
                }

                if (!found && _9gtable_size > 0)
                {
                    found = FindTablePath(_9g_table, _9gtable_size, name, name);
                }

                if (!found && _10gtable_size > 0)
                {
                    found = FindTablePath(_10g_table, _10gtable_size, name, name);
                }

                if (!found && _11gtable_size > 0)
                {
                    found = FindTablePath(_11g_table, _11gtable_size, name, name);
                }
                if (!found && _12gtable_size > 0)
                {
                    found = FindTablePath(_12g_table, _12gtable_size, name, name);
                }

                if (!found)
                {
                    printf("Part 1 Error: cannot find path of %s.\n", name);
                    //printf("Warning: first cannot find path of %s\n", name);
                    //sceKernelDelayThread(2*1000*1000);
                    continue;
                }
            }
        }

        else if (!strncmp(name, "com:", 4) && comtable_size > 0)
        {
            if (!FindTablePath(com_table, comtable_size, name+4, name))
            {
                printf("Part 2 Error: cannot find path of %s.\n", name);
                //printf("Warning: second cannot find path of %s\n", name);
                //sceKernelDelayThread(2*1000*1000);
                continue;
                //printf("Error: cannot find path of %s.\n", name);
            }
        }

        else if (!strncmp(name, "01g:", 4) && _1gtable_size > 0)
        {
            if (!FindTablePath(_1g_table, _1gtable_size, name+4, name))
            {
                printf("Error: 01g cannot find path of %s.\n", name);
            }
        }

        else if (!strncmp(name, "02g:", 4) && _2gtable_size > 0)
        {
            if (!FindTablePath(_2g_table, _2gtable_size, name+4, name))
            {
                printf("Error: 01g cannot find path of %s.\n", name);
            }
        }

        printf("'%s' ", name);

        const char* szFileBase = strrchr(name, '/');

        if (szFileBase != NULL)
            szFileBase++;  // after slash
        else
            szFileBase = "err.err";

        if (cbExpanded > 0)
        {
            std::string szDataPath;

            if (!strncmp(name, "flash0:/", 8))
            {
                szDataPath = outdir + "/F0/" + (name + 8);
            }

            else if (!strncmp(name, "flash1:/", 8))
            {
                szDataPath = outdir + "/F1/" + (name + 8);
            }

            else if (!strcmp(name, "com:00000"))
            {
                comtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (comtable_size <= 0)
                {
                    printf("Cannot decrypt common table.\n");
                }

                if (comtable_size > sizeof(com_table))
                {
                    printf("Com table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(com_table, data2, comtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/common_files_table.bin";
            }

            else if (!strcmp(name, "01g:00000") || !strcmp(name, "00001"))
            {
                _1gtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (_1gtable_size <= 0)
                {

                    printf("Cannot decrypt 1g table.\n");

                }

                if (_1gtable_size > sizeof(_1g_table))
                {
                    printf("1g table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(_1g_table, data2, _1gtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/1000_files_table.bin";
            }
            else if (!strcmp(name, "02g:00000") || !strcmp(name, "00002"))
            {
                _2gtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (_2gtable_size <= 0)
                {
                    printf("Cannot decrypt 2g table %08X.\n", _2gtable_size);
                }

                if (_2gtable_size > sizeof(_2g_table))
                {
                    printf("2g table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(_2g_table, data2, _2gtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/2000_files_table.bin";
            }

            else if (!strcmp(name, "00003"))
            {
                _3gtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (_3gtable_size <= 0)
                {
                    // We don't have yet the keys for table of 3000, they are only in mesg_led03g.prx
                    printf("Cannot decrypt 3g table %08X.\n", _3gtable_size);
                    continue;
                }

                if (_3gtable_size > sizeof(_3g_table))
                {
                    printf("3g table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(_3g_table, data2, _3gtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/3000_files_table.bin";
            }
            else if (!strcmp(name, "00004"))
            {
                _4gtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (_4gtable_size <= 0)
                {
                    printf("Cannot decrypt 4g table %08X.\n", _4gtable_size);
                    continue;
                }

                if (_4gtable_size > sizeof(_4g_table))
                {
                    printf("4g table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(_4g_table, data2, _4gtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/4000_files_table.bin";
            }
            else if (!strcmp(name, "00005"))
            {
                _5gtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (_5gtable_size <= 0)
                {
                    _5gtable_size = pspDecryptTable(data2, data1, cbExpanded, 5);
                    if (_5gtable_size <= 0)
                    {
                        printf("Cannot decrypt 5g table %08X [tag %08X].\n", _5gtable_size, (u32)*(u32_le*)&data2[0xD0]);
                        continue;
                    }
                }

                if (_5gtable_size > sizeof(_5g_table))
                {
                    printf("5g table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(_5g_table, data2, _5gtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/5000_files_table.bin";
            }
            else if (!strcmp(name, "00006"))
            {
                _6gtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (_6gtable_size <= 0)
                {
                    printf("Cannot decrypt 6g table %08X.\n", _6gtable_size);
                    continue;
                }

                if (_6gtable_size > sizeof(_6g_table))
                {
                    printf("6g table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(_6g_table, data2, _6gtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/6000_files_table.bin";
            }
            else if (!strcmp(name, "00007"))
            {
                _7gtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (_7gtable_size <= 0)
                {
                    printf("Cannot decrypt 7g table %08X.\n", _7gtable_size);
                    continue;
                }

                if (_7gtable_size > sizeof(_7g_table))
                {
                    printf("7g table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(_7g_table, data2, _7gtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/7000_files_table.bin";
            }
            else if (!strcmp(name, "00008"))
            {
                _8gtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (_8gtable_size <= 0)
                {
                    printf("Cannot decrypt 8g table %08X.\n", _8gtable_size);
                    continue;
                }

                if (_8gtable_size > sizeof(_8g_table))
                {
                    printf("8g table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(_8g_table, data2, _8gtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/8000_files_table.bin";
            }
            else if (!strcmp(name, "00009"))
            {
                _9gtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (_9gtable_size <= 0)
                {
                    printf("Cannot decrypt 9g table %08X.\n", _9gtable_size);
                    continue;
                }

                if (_9gtable_size > sizeof(_9g_table))
                {
                    printf("9g table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(_9g_table, data2, _9gtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/9000_files_table.bin";
            }
            else if (!strcmp(name, "00010"))
            {
                _10gtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (_10gtable_size <= 0)
                {
                    printf("Cannot decrypt 10g table %08X.\n", _10gtable_size);
                    continue;
                }

                if (_10gtable_size > sizeof(_10g_table))
                {
                    printf("10g table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(_10g_table, data2, _10gtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/10000_files_table.bin";
            }
            else if (!strcmp(name, "00011"))
            {
                _11gtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (_11gtable_size <= 0)
                {
                    printf("Cannot decrypt 11g table %08X.\n", _11gtable_size);
                    continue;
                }

                if (_11gtable_size > sizeof(_11g_table))
                {
                    printf("11g table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(_11g_table, data2, _11gtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/11000_files_table.bin";
            }
            else if (!strcmp(name, "00012"))
            {
                _12gtable_size = pspDecryptTable(data2, data1, cbExpanded, table_mode);

                if (_12gtable_size <= 0)
                {
                    printf("Cannot decrypt 12g table %08X.\n", _12gtable_size);
                    continue;
                }

                if (_12gtable_size > sizeof(_12g_table))
                {
                    printf("12g table buffer too small. Recompile with bigger buffer.\n");
                }

                memcpy(_12g_table, data2, _12gtable_size);
                szDataPath = outdir + "/F0/PSARDUMPER/12000_files_table.bin";
            }

            else
            {
                szDataPath = outdir + "/F0/PSARDUMPER/" + (strrchr(name, '/') + 1);
            }

            printf("expanded");

            if (signcheck && mode == MODE_ENCRYPT_SIGCHECK
                && (strcmp(name, "flash0:/kd/loadexec.prx") != 0)
                && (strcmp(name, "flash0:/kd/loadexec_01g.prx") != 0)
                && (strcmp(name, "flash0:/kd/loadexec_02g.prx") != 0)
                && (strcmp(name, "flash0:/kd/loadexec_03g.prx") != 0)
                && (strcmp(name, "flash0:/kd/loadexec_04g.prx") != 0)
                && (strcmp(name, "flash0:/kd/loadexec_05g.prx") != 0)
                && (strcmp(name, "flash0:/kd/loadexec_06g.prx") != 0)
                && (strcmp(name, "flash0:/kd/loadexec_07g.prx") != 0)
                && (strcmp(name, "flash0:/kd/loadexec_08g.prx") != 0)
                && (strcmp(name, "flash0:/kd/loadexec_09g.prx") != 0))
            {
                pspSignCheck(data2);
            }

            if ((mode != MODE_DECRYPT) || (memcmp(data2, "~PSP", 4) != 0))
            {
                if (strncmp(name, "ipl:", 4) == 0 && *(u32*)(data2 + 0x60) != 1)
                {
                    // IPL Pre-decryption
                    cbExpanded = pspDecryptPRX(data2, data1, cbExpanded);

                    if (cbExpanded <= 0)
                    {
                        printf(",pre-decrypt failed");
                    }
                    else
                    {
                        printf(",pre-decrypt ok");
                        memcpy(data2, data1, cbExpanded);
                    }
                }

                if (WriteFile(szDataPath.c_str(), data2, cbExpanded) != cbExpanded)
                {
                    printf("Cannot write %s.\n", szDataPath.c_str());
                    break;
                }

                printf(",saved");
                CheckExtractReboot(name, mode, data2, cbExpanded, data1, data2, outdir);
            }
            if ((memcmp(data2, "~PSP", 4) == 0 || strncmp(name, "flash0:/kd/resource/me", 22) == 0) &&
                (mode == MODE_DECRYPT))
            {
                int cbDecrypted = pspDecryptPRX(data2, data1, cbExpanded);

                // output goes back to main buffer
                // trashed 'data2'
                if (cbDecrypted > 0)
                {
                    u8* pbToSave = data1;
                    int cbToSave = cbDecrypted;

                    printf(",decrypted");

                    if ((data1[0] == 0x1F && data1[1] == 0x8B) ||
                        memcmp(data1, "2RLZ", 4) == 0 || memcmp(data1, "KL4E", 4) == 0)
                    {
                        int cbExp = pspDecompress(data1, cbToSave, data2, 3000000);

                        if (cbExp > 0)
                        {
                            printf(",expanded");
                            pbToSave = data2;
                            cbToSave = cbExp;
                        }
                        else
                        {
                            printf(",decompress error");
                            //printf("Decompress error 0x%08X\n"
                            //       "File will be written compressed.\n", cbExp);
                        }
                    }

                    if (WriteFile(szDataPath.c_str(), pbToSave, cbToSave) != cbToSave)
                    {
                        printf("Error writing %s.\n", szDataPath.c_str());
                    }

                    printf(",saved!");
                    CheckExtractReboot(name, mode, pbToSave, cbToSave, data1, data2, outdir);
                }
                else
                {

                    printf(",error during decryption [tag %08x].", (u32)*(u32_le*)&data2[0xD0]);

                }
            }

            else if (strncmp(name, "ipl:", 4) == 0)
            {
                int cb1 = pspDecryptIPL1(data2, data1, cbExpanded);
                if (cb1 > 0)
                {
                    printf(",decrypted IPL");
                    u32 addr;
                    int cb2 = pspLinearizeIPL2(data1, data2, cb1, &addr);
                    szDataPath = outdir + "/F0/PSARDUMPER/stage1_" + szFileBase;
                    if (cb2 > 0 && WriteFile(szDataPath.c_str(), data2, cb2))
                    {
                        printf(",linearized at %08x", addr);
                    }
                    else
                    {
                        printf(",failed linearizing");
                    }

                    if (decryptIPL(data2, cb2, intVersion, addr, szFileBase, outdir) != 0)
                    {
                        printf(",failed IPL stages decryption");
                    }
                }
                else
                {
                    printf(",failed decrypting IPL");
                }
            }
        }
        else if (cbExpanded == 0)
        {
            printf("empty");
        }

        printf("\n");
    }
    printf("Done!\n");

    return 0;
}
