/*
 * Code partly taken from newpsardumper-660
 * See PsarDecrypter.cpp for details.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/des.h>

extern "C" {
#include "libkirk/kirk_engine.h"
#include "kl4e.h"
#include "libLZR.h"
}
#include "pspdecrypt_lib.h"
#include "PrxDecrypter.h"
#include "common.h"

////////// SignCheck //////////

u8 check_keys0[0x10] =
{
	0x71, 0xF6, 0xA8, 0x31, 0x1E, 0xE0, 0xFF, 0x1E,
	0x50, 0xBA, 0x6C, 0xD2, 0x98, 0x2D, 0xD6, 0x2D
};

u8 check_keys1[0x10] =
{
	0xAA, 0x85, 0x4D, 0xB0, 0xFF, 0xCA, 0x47, 0xEB,
	0x38, 0x7F, 0xD7, 0xE4, 0x3D, 0x62, 0xB0, 0x10
};

static int Encrypt(u32 *buf, int size)
{
	buf[0] = 4;
	buf[1] = buf[2] = 0;
	buf[3] = 0x100;
	buf[4] = size;

	/* Note: this encryption returns different data in each psp,
	   But it always returns the same in a specific psp (even if it has two nands) */
	if (sceUtilsBufferCopyWithRange((u8*)buf, size+0x14, (u8*)buf, size+0x14, 5) != 0)
		return -1;

	return 0;
}

int pspSignCheck(u8 *buf)
{
	u8 enc[0xD0+0x14];
	int iXOR, res;

	memcpy(enc+0x14, buf+0x110, 0x40);
	memcpy(enc+0x14+0x40, buf+0x80, 0x90);
	
	for (iXOR = 0; iXOR < 0xD0; iXOR++)
	{
		enc[0x14+iXOR] ^= check_keys0[iXOR&0xF];
	}

	if ((res = Encrypt((u32 *)enc, 0xD0)) != 0)
	{
		printf("Encrypt failed.\n");
		return -1;
	}

	for (iXOR = 0; iXOR < 0xD0; iXOR++)
	{
		enc[0x14+iXOR] ^= check_keys1[iXOR&0xF];
	}

	memcpy(buf+0x80, enc+0x14, 0xD0);
	
	return 0;
}

int pspIsSignChecked(u8 *buf)
{
	int i, res = 0;

	for (i = 0; i < 0x58; i++)
	{
		if (buf[0xD4+i] != 0)
		{
			res = 1;
			break;
		}
	}

	return res;
}

////////// UnsignCheck //////////

static int Decrypt(u32 *buf, int size)
{
	buf[0] = 5;
	buf[1] = buf[2] = 0;
	buf[3] = 0x100;
	buf[4] = size;

	if (sceUtilsBufferCopyWithRange((u8*)buf, size+0x14, (u8*)buf, size+0x14, 8) != 0)
		return -1;
	
	return 0;
}

int pspUnsignCheck(u8 *buf)
{
	u8 enc[0xD0+0x14];
	int iXOR, res;

	memcpy(enc+0x14, buf+0x80, 0xD0);

	for (iXOR = 0; iXOR < 0xD0; iXOR++)
	{
		enc[iXOR+0x14] ^= check_keys1[iXOR&0xF]; 
	}

	if ((res = Decrypt((u32 *)enc, 0xD0)) < 0)
	{
		printf("Decrypt failed.\n");
		return res;
	}

	for (iXOR = 0; iXOR < 0xD0; iXOR++)
	{
		enc[iXOR] ^= check_keys0[iXOR&0xF];
	}

	memcpy(buf+0x80, enc+0x40, 0x90);
	memcpy(buf+0x110, enc, 0x40);

	return 0;
}

int kirk1block(const u8 *pbIn, u8 *pbOut)
{
    static u8 g_dataTmp[0x1040] __attribute__((aligned(0x40)));
    memcpy(g_dataTmp+0x40, pbIn, 0x1000);
    int ret = sceUtilsBufferCopyWithRange(g_dataTmp, 0x1040, g_dataTmp+0x40, 0x500, 1);
    if (ret != 0) {
        return ret;
    }
    memcpy(pbOut, g_dataTmp, 0x1000);
    return 0;
}

/* xor keys & original descrambling code thanks to Davee and Proxima's awesome work! */
u32 xorkeys[] = {
    0x61A0C918, 0x45695E82, 0x9CAFD36E, 0xFA499B0F,
    0x7E84B6E2, 0x91324D29, 0xB3522009, 0xA8BC0FAF,
    0x48C3C1C5, 0xE4C2A9DC, 0x00012ED1, 0x57D9327C,
    0xAFB8E4EF, 0x72489A15, 0xC6208D85, 0x06021249,
    0x41BE16DB, 0x2BD98F2F, 0xD194BEEB, 0xD1A6E669,
    0xC0AC336B, 0x88FF3544, 0x5E018640, 0x34318761,
    0x5974E1D2, 0x1E55581B, 0x6F28379E, 0xA90E2587,
    0x091CB883, 0xBDC2088A, 0x7E76219C, 0x9C4BEE1B,
    0xDD322601, 0xBB477339, 0x6678CF47, 0xF3C1209B,
    0x5A96E435, 0x908896FA, 0x5B2D962A, 0x7FEC378C,
    0xE3A3B3AE, 0x8B902D93, 0xD0DF32EF, 0x6484D261,
    0x0A84A153, 0x7EB16575, 0xB10E53DD, 0x1B222753,
    0x58DD63D0, 0x8E8B8D48, 0x755B32C2, 0xA63DFFF7,
    0x97CABF7C, 0x33BDC660, 0x64522286, 0x403F3698,
    0x3406C651, 0x9F4B8FB9, 0xE284F475, 0xB9189A13,
    0x12C6F917, 0x5DE6B7ED, 0xDB674F88, 0x06DDB96E,
    0x2B2165A6, 0x0F920D3F, 0x732B3475, 0x1908D613
};

u32 bitrev(u32 b) {
    u32 i = 0;
    u32 x = 0;
    for (i = 0; i < 32; i++) {
        x |= ((b & (1<<i))>>i) << (0x1F-i);
    }
    return x;
}

// Additional scrambling for 03g+ IPLs
void descramble03g(u32 *data, u32 i)
{
    u32 idx = (i >> 5) & 0x3F;
    u32 rot = i & 0x1F;
    u32 x1 = xorkeys[idx];
    u32 x2 = xorkeys[idx+1];
    u32 x3 = xorkeys[idx+2];
    u32 x4 = xorkeys[idx+3];
    x1 = ((x1 >> rot) | (x1 << (0x20-rot)));
    x2 = bitrev(((x2 >> rot) | (x2 << (0x20-rot))));
    x3 = (((x3 >> rot) | (x3 << (0x20-rot)))  ^ x4);
    x4 = ((x4 >> rot) | (x4 << (0x20-rot)));
    data[0] ^= x1;
    data[1] ^= x2;
    data[2] ^= x3;
    data[3] ^= x4;
}

////////// IPL Decryption /////////
int pspDecryptIPL1(const u8* pbIn, u8* pbOut, int cbIn)
{
    int cbOut = 0;
    int xorkeyIdx = -1;
    while (cbIn >= 0x1000)
    {
        if (pbIn[0x62] == 1) {
            u8 decData[0x1000];
            memcpy(decData, pbIn, 0x1000);
            decData[0x62] = 0;
            // In practice, xorkeyIdx = 2 on 05g and xorkeyIdx = 1 on the other models, but who knows
            if (xorkeyIdx == -1) {
                u32 i;
                for (i = 0; i < 0x7E0; i++) {
                    descramble03g((u32*)decData, i);
                    int ret = kirk1block(decData, pbOut);
                    if (ret == 0) {
                        break;
                    }
                    memcpy(decData, pbIn, 16); // reset header
                }
                if (i == 0x7E0) {
                    printf("Decrypt IPL 1 for 03g+ failed for first block!\n");
                    break;
                }
                xorkeyIdx = i;
                printf(",descramble using xorkey %d", xorkeyIdx);
            } else {
                descramble03g((u32*)decData, xorkeyIdx);
                int ret = kirk1block(decData, pbOut);
                if (ret != 0) {
                    printf("Decrypt IPL 1 for 03g+ failed for other blocks!\n");
                    break;
                }
            }
        } else {
            int ret = kirk1block(pbIn, pbOut);
	        if (ret != 0)
            {
	            printf("Decrypt IPL 1 failed 0x%08X, WTF!\n", ret);
                break; // stop, save what we can
            }
        }
        pbIn += 0x1000;
        cbIn -= 0x1000;
        pbOut += 0x1000;
        cbOut += 0x1000;
    }

    return cbOut;
}

int pspLinearizeIPL2(const u8* pbIn, u8* pbOut, int cbIn, u32 *startAddr)
{
	u32 nextAddr = 0;
    int cbOut = 0;
    while (cbIn > 0)
    {
        u32* pl = (u32*)pbIn;
        u32 addr = pl[0];

        if (addr != nextAddr && nextAddr != 0)
        {
            return 0;   // error
        }

        if (nextAddr == 0) {
            *startAddr = addr;
        }

        u32 count = pl[1];
        nextAddr = addr + count;
        memcpy(pbOut, pbIn+0x10, count);
        pbOut += count;
        cbOut += count;
        pbIn += 0x1000;
        cbIn -= 0x1000;
    }

    return cbOut;
}

////////// Decompression //////////

int pspIsCompressed(u8 *buf)
{
	int res = 0;

	if (buf[0] == 0x1F && buf[1] == 0x8B)
		res = 1;
	else if (memcmp(buf, "2RLZ", 4) == 0)
		res = 1;

	return res;
}

int pspDecompress(u8 *inbuf, u32 insize, u8 *outbuf, u32 outcapacity)
{
	int retsize;
	
	if (inbuf[0] == 0x1F && inbuf[1] == 0x8B) 
	{
	    retsize = gunzip(inbuf, insize, outbuf, outcapacity);
	    printf(",gzip");
	}
	else if (memcmp(inbuf, "2RLZ", 4) == 0) 
	{
	    retsize = LZRDecompress(outbuf, outcapacity, inbuf+4, NULL);
		printf(",lzrc");
	}
	else if (memcmp(inbuf, "KL4E", 4) == 0)
	{
		retsize = decompress_kle(outbuf, outcapacity, inbuf+4, NULL, 1);
		printf(",kl4e");
	}
	else if (memcmp(inbuf, "KL3E", 4) == 0) 
	{
		retsize = decompress_kle(outbuf, outcapacity, inbuf+4, NULL, 0);
		printf(",kl3e");
	}
	else
	{
		retsize = -1;
	}

	return retsize;
}

////////// DES Table decryption //////////

typedef struct
{
    u8 key[8];
    u8 iv[8];
} TABLE_KEYS;

TABLE_KEYS table_keys[] =
{
    {{ 0x95, 0x62, 0x0B, 0x49, 0xB7, 0x30, 0xE5, 0xC7 }, { 0x9E, 0xA4, 0x33, 0x81, 0x86, 0x0C, 0x52, 0x85 }},
    {{ 0x5A, 0x7B, 0x3D, 0x9D, 0x45, 0xC9, 0xDC, 0x95 }, { 0xB2, 0xFE, 0xD9, 0x79, 0x8A, 0x02, 0xB1, 0x87 }},
    {{ 0x4C, 0xCE, 0x49, 0x5B, 0x6F, 0x20, 0x58, 0x5A }, { 0x81, 0x08, 0xC1, 0xF2, 0x35, 0x98, 0x69, 0xB0 }},
    {{ 0x73, 0xF4, 0x52, 0x62, 0x62, 0x0B, 0xF1, 0x5A }, { 0x6D, 0x52, 0x1B, 0xA3, 0xC2, 0x36, 0xF9, 0x2B }},
    {{ 0xA6, 0x64, 0xC8, 0xF8, 0xFD, 0x9D, 0x44, 0x98 }, { 0xDB, 0x4E, 0x79, 0x41, 0xF5, 0x97, 0x30, 0xAD }},
    {{ 0xD7, 0xBD, 0x74, 0x81, 0x3D, 0x64, 0x26, 0xE7 }, { 0xA6, 0x83, 0x0C, 0x2F, 0x63, 0x0B, 0x96, 0x29 }},
};

static void DecryptT(u8 *buf, int size, int mode)
{
    DES_key_schedule schedule;
    DES_set_key_unchecked((DES_cblock*)&table_keys[mode].key, &schedule);
    DES_cbc_encrypt(buf, buf, size, &schedule, (DES_cblock*)&table_keys[mode].iv, DES_DECRYPT);
}

int pspDecryptTable(u8 *buf1, u8 *buf2, int size, int mode)
{
	int retsize;

	if (buf1 != buf2) memcpy(buf2, buf1, size);

	DecryptT(buf2, size, mode);

	retsize = pspDecryptPRX(buf2, buf1, size);
	if (retsize < 0)
	{	
	    retsize = -1;
	}

	return retsize;
}

