#include <cstdint>
#include <cstring>
#include <cstdio>
#include <openssl/sha.h>
#include <map>
#include <array>

#include "CommonTypes.h"
#include "common.h"

extern "C" {
#include "libkirk/kirk_engine.h"
}

/*
// Add this if you want to compute the keys yourself!
#include "preipl.h"
#define PREIPL
#define PREIPL_SIZE 4096
*/

#define max(a, b) ((a) < (b) ? (b) : (a))

const bool debug = false;

// 3.80+ use a custom Sha256 (with different initialization constants and the output truncated to 28 bytes), in part1 only
int g_customSha = 0;
// Use a SFMT19937 PRNG instead of MT19937 starting with 3.80 in part2 and 5.05 also in part1
int g_useSfmt = 0;
// 3.10+ have an additional unused round of MT19937
int g_emptyRound = 0;
// 1 if we use a precomputed key (see below), which avoids requiring a pre-ipl dump at hand
int g_usePrecomp = 0;
std::array<u32, 8> g_precompKey;

// In 3.30+, derive the key from a scrambled key first (g_newKey) and if the key's checksum is equal to g_checksum,
// XOR it with g_xorKey. Probably used to handle several preipl versions.
u8 *g_newKey;
u8 *g_xorKey;
u8 g_checksum;

// Keys from preipl sha256 1e6fc02124901f6f5a3f1bb02f065064c63e423d759a131ba1086ea8fc2d90aa
std::map<u32, std::array<u32, 8>> g_keys {
    {0x3ca104f4, {0x351934f6, 0x7c77b627, 0xc774d96b, 0xac1381ef, 0xa93ba068, 0x9bf7a518, 0xd7e040e4, 0x41d18c07}}, // 2.60
    {0x3f0449dd, {0x941a62b7, 0xa8b33d7e, 0xf59f3d90, 0xbfe0a24d, 0x295206e9, 0xe8d280fa, 0xb705572a, 0x99ad3262}}, // 2.7x
    {0xfcc312e8, {0x4ebb9a84, 0x9d5b13a5, 0x569beec5, 0x343d4264, 0x2b3896dd, 0x00c962d8, 0x09fca971, 0x6aa5bcff}}, // 2.8x
    {0x73acd410, {0xa06c226a, 0x3aee5334, 0x580f1057, 0x8a54f529, 0x1f4baece, 0xfa1d193e, 0x8ebb3a3c, 0x9e71ebfe}}, // 3.0x
    {0x09cad2e0, {0x3311ea3a, 0xabc9231f, 0xdc31a4ec, 0x854344a5, 0x3c4ab211, 0x3db9632c, 0xbffe001b, 0xe4cd2a5b}}, // 3.1x
    {0x59240761, {0x7c88b8f4, 0xf37ac9f8, 0xcedd8523, 0x1ed52bb3, 0xe02a117b, 0xad733c35, 0x34e7d318, 0x96434aac}}, // 3.30, 3.40
    {0x3223e3dd, {0x3ff5e39a, 0x6f09bd05, 0xeb912e7f, 0xdf288223, 0xede00faa, 0x2187f747, 0x1e05d1e7, 0xbc699822}}, // 3.5x
    {0xbf94b233, {0xbe73e05c, 0xde908e11, 0xa08ec1df, 0xd52c8f15, 0x85cf2ad7, 0x16c21b33, 0x2c0e43e8, 0x084742b2}}, // 3.7x 01g
    {0xc93aaf8e, {0x678ff79a, 0xa6a3e8cf, 0xa3440e80, 0xbfe1a980, 0x1734fb62, 0x8c8dcf35, 0x4b0443fd, 0xd4ecf146}}, // 3.7x 02g
    {0xda8611e4, {0xfb9f9a86, 0x8dec7ddc, 0xb32215f0, 0x5e7be11f, 0xa6a140d7, 0xff068276, 0x2b2ee6e1, 0x00000000}}, // 3.80, 3.90, 3.93 01g
    {0x0bb77011, {0xf4710af6, 0x46a34052, 0xdef91911, 0x29afe7d7, 0xc7fc1e55, 0xd0838eb1, 0xe069efd4, 0x00000000}}, // 3.80, 3.90, 3.93 02g
    {0x8f94e800, {0xe359cf7e, 0x0c497ceb, 0x5ddf77c8, 0xf9bd7557, 0x00f4c84e, 0xe8b8bb30, 0x9417a01f, 0x00000000}}, // 3.95, 3.96, 4.0x 01g
    {0x835f216c, {0xbd44491e, 0x2846ad03, 0x8ab0052e, 0x800e913b, 0x311ac562, 0x164bcb2c, 0x47791324, 0x00000000}}, // 3.95, 3.96, 4.0x 02g
    {0xf6d67166, {0xc9d132c6, 0x39bf60aa, 0x1e0beb42, 0x2527c8aa, 0xee9568c7, 0xc1e9c001, 0xe12d8a28, 0x00000000}}, // 5.00, 5.01, 5.02, 5.03 01g
    {0x1d3b3e5c, {0x0bdc608a, 0xb798378c, 0xd7685fca, 0x2eff316c, 0x360b71bd, 0x54cf987b, 0xa33e199f, 0x00000000}}, // 5.00, 5.01, 5.02, 5.03 02g
    {0x3c5001d1, {0xc875123f, 0x91729205, 0x3ecf796e, 0xe4d1ed01, 0xb4a21262, 0xe2393966, 0x652c02a0, 0x00000000}}, // 5.05, 5.50, 5.51 01g
    {0x34da9f9e, {0xd5598f66, 0x76563204, 0xd7609af3, 0x19e3fdfd, 0x59423449, 0x51f66969, 0x7491d7c7, 0x00000000}}, // 5.05, 5.50, 5.51 02g
    {0xdd076132, {0xba731b75, 0xcc82b010, 0xeb35b72f, 0xcc228644, 0x56d6ba1e, 0x0d53c995, 0x988869a6, 0x00000000}}, // 5.55 01g
    {0x03860456, {0xa35e7406, 0x8f85a45c, 0x73da7972, 0x2b231cda, 0x0352d13b, 0x1a5a0926, 0x86e6b2aa, 0x00000000}}, // 5.55 02g
    {0xbd0cd90b, {0xaa80ca25, 0x8686d001, 0x2af2ed65, 0x77b0ca3a, 0xb608924f, 0x8454d567, 0xfb1a3e15, 0x00000000}}, // 6.00, 6.10, 6.20 01g
    {0x66e25e99, {0xd7af4f1e, 0x7cac691f, 0xc45ddbc2, 0x80c62fbf, 0x74928262, 0x36adec73, 0x9f38dbe9, 0x00000000}}, // 6.00, 6.10, 6.20 02g
    {0xdf2909ba, {0xcd9c739f, 0x5077f132, 0x64079858, 0x01890036, 0x18bda892, 0xc31afe19, 0x309d6b46, 0x00000000}}, // 6.3x 01g
    {0x545f427d, {0x1039fa9d, 0x4dbb2c77, 0x85c4f2c2, 0x51603084, 0x45190185, 0x0dea4d7d, 0x9c2853b8, 0x00000000}}, // 6.3x 02g
    {0x5eb2f991, {0x5ccf8527, 0x2ff4adbb, 0x90c4a5ff, 0x64a5a0b3, 0xe2db29d9, 0x4a3507db, 0x51cf76e7, 0x00000000}}, // 6.6x 01g
    {0xfeadb708, {0x54db38ee, 0x84cfaea2, 0xf85925fb, 0xcba099a5, 0x9292dfab, 0xffa59b39, 0x5db31507, 0x00000000}}, // 6.6x 02g
};

s32 sha256Digest(u8 *data, u32 size, u8 *digest);

void SHA256_Init2(SHA256_CTX *ctx)
{
    SHA256_Init(ctx);
    if (g_customSha) {
        ctx->h[0] = 0xC1059ED8;
        ctx->h[1] = 0x367CD507;
        ctx->h[2] = 0x3070DD17;
        ctx->h[3] = 0xF70E5939;
        ctx->h[4] = 0xFFC00B31;
        ctx->h[5] = 0x68581511;
        ctx->h[6] = 0x64F98FA7;
        ctx->h[7] = 0xBEFA4FA4;
    }
}

void SHA256_Final2(u8 *digest, SHA256_CTX *ctx)
{
    // Custom sha256 is only 7 words of output long, so we need to backup the last word
    u8 back[4];
    memcpy(back, digest + 28, 4);
    SHA256_Final(digest, ctx);
    if (g_customSha) {
        memcpy(digest + 28, back, 4);
    }
}

void scrambleBuf(u8 *in1, u32 inSize1, u8 *in2, u32 inSize2, u8 *out) // at 0x040F0C08 in 2.60
{
    SHA256_CTX ctx; // sp
    u8 buf1[32]; // sp + 112 // actually 28 in 3.80+
    u8 buf2[64]; // sp + 144
    if (inSize2 == 0 || in2 == NULL) {
        sha256Digest(in1, inSize1, out);
        return;
    }
    // 0C78
    memset(buf2, 0, 64);
    if (inSize1 > 64) {
        // 0D5C
        sha256Digest(in1, inSize1, buf2);
    } else {
        memcpy(buf2, in1, inSize1);
    }
    // 0CAC
    for (s32 i = 0; i < 64; i++) {
        buf2[i] ^= 0x36;
    }
    SHA256_Init2(&ctx);
    SHA256_Update(&ctx, buf2, 64);
    SHA256_Update(&ctx, in2, inSize2);
    SHA256_Final2(buf1, &ctx);
    // 0D04
    for (s32 i = 0; i < 64; i++) {
        buf2[i] ^= 0x6A;
    }
    SHA256_Init2(&ctx);
    SHA256_Update(&ctx, buf2, 64);
    SHA256_Update(&ctx, buf1, g_customSha ? 28 : 32);
    SHA256_Final2(out, &ctx);
    // in 3.30+, here ctx, buf1 and buf2 are memset to 0
}

typedef struct _SceKernelUtilsMt19937Context {
    unsigned int    count;
    unsigned int    state[624];
} SceKernelUtilsMt19937Context;

u32 mt19937UInt(SceKernelUtilsMt19937Context *ctx) // at 0x040F1890
{
    u32 initCount = ctx->count;
    u32 prevState = ctx->state[ctx->count];
    u32 curState;
    if (ctx->count >= 623) {
        // 1938
        ctx->count = 0;
    } else {
        ctx->count++;
    }
    curState = ctx->state[ctx->count];
    // 18C0
    u32 x = (prevState & 0x80000000) | (curState & ~0x80000000);
    x >>= 1;
    u32 z;
    if (initCount < 227)
        z = ctx->state[initCount + 397];
    else
        z = ctx->state[initCount - 227];
    if ((curState & 1) != 0)
        x ^= 0x9908B0DF;
    ctx->state[initCount] = x ^ z;
    u32 y = prevState ^ (prevState >> 11);
    y ^= ((y << 7) & 0x9D2C5680);
    y ^= ((y << 15) & 0xEFC60000);
    y ^= (y >> 18);
    return y;
}

// from uofw, sceKernelUtilsMt19937Init
// used in 3.30+ only
int mt19937Init(SceKernelUtilsMt19937Context *ctx, u32 seed) // at 0x040F1B30
{
    ctx->state[0] = seed;
    int i;
    for (i = 1; i < 624; i++)
        ctx->state[i] = (ctx->state[i - 1] ^ (ctx->state[i - 1] >> 30)) * 0x6C078965 + i;
    ctx->count = 0;
    for (i = 0; i < 624; i++)
        mt19937UInt(ctx);
    return 0;
}

// Note: this function doesn't respect calling conventions and uses t8, t9, v1, at for the constants
u32 *sfmtShuffle(u32 *outBuf, u32 *inBuf1, u32 *inBuf2, u32 *inBuf3, u32 *inBuf4) // at 0x04003330  for 3.80 part2
{
    u32 t0, t1, t2, t3, t4, t5, t6, t7;
    t0 = inBuf1[0];
    t1 = inBuf1[1];
    t2 = inBuf1[2];
    t3 = inBuf1[3];
    t0 ^=                              (inBuf1[0] << 8);
    t1 ^= ((inBuf1[0] >> 24) & 0xFF) | (inBuf1[1] << 8);
    t2 ^= ((inBuf1[1] >> 24) & 0xFF) | (inBuf1[2] << 8);
    t3 ^= ((inBuf1[2] >> 24) & 0xFF) | (inBuf1[3] << 8);
    t0 ^= (inBuf2[0] >> 11) & 0xDFFFFFEF;
    t1 ^= (inBuf2[1] >> 11) & 0xDDFECB7F;
    t2 ^= (inBuf2[2] >> 11) & 0xBFFAFFFF;
    t3 ^= (inBuf2[3] >> 11) & 0xBFFFFFF6;
    t4 = (inBuf3[0] >> 8) | (inBuf3[1] << 24);
    t5 = (inBuf3[1] >> 8) | (inBuf3[2] << 24);
    t6 = (inBuf3[2] >> 8) | (inBuf3[3] << 24);
    t7 = (inBuf3[3] >> 8);
    outBuf[0] = t0 ^ t4 ^ (inBuf4[0] << 18);
    outBuf[1] = t1 ^ t5 ^ (inBuf4[1] << 18);
    outBuf[2] = t2 ^ t6 ^ (inBuf4[2] << 18);
    outBuf[3] = t3 ^ t7 ^ (inBuf4[3] << 18);
    return outBuf;
}

u32 sfmtUInt(SceKernelUtilsMt19937Context *ctx) // at 0x04003428 
{
    u32 curCount = ctx->count;
    if (curCount++ < 624) {
        ctx->count = curCount;
        return ctx->state[curCount - 1];
    }
    // 3488
    u32 *state1 = &ctx->state[616];
    u32 *state2 = &ctx->state[620];
    // 34D8
    u32 i = 0;
    for (; i < 34; i++) {
        u32 *a0 = &ctx->state[i * 4];
        u32 *newState = sfmtShuffle(a0, a0, a0 + 488, state1, state2);
        state1 = state2;
        state2 = newState;
    }
    // 350C
    for (; i < 156; i++) {
        u32 *a0 = &ctx->state[i * 4];
        u32 *newState = sfmtShuffle(a0, a0, a0 - 136, state1, state2);
        state1 = state2;
        state2 = newState;
    }
    /* Unused here (disabled function?)
    a0 = ctx;
    v1 = a0 & 0x1;
    a0 = (a0 & 0xFFFFFFFE) | ((0 << 0) & 0x00000001);
    ctx->count = v1 + 1;
    */
    ctx->count = 1;
    /* Unused (weird here, maybe used by a disabled function?)
    if (v1 != 0) {
        v1 = ctx->state[1];
    }
    */
    return ctx->state[0];
}

u32 g_sfmtParity[4] = {1, 0, 0, 0x13C9E684};

void sfmtCertify(SceKernelUtilsMt19937Context *ctx) // at 0x0400378C  in 3.80 part2
{
    u32 v0 = 0;
    // 37A0
    for (s32 i = 0; i < 4; i++) {
        u32 state = ctx->state[i] & g_sfmtParity[i];
        state ^= state >> 16;
        state ^= state >> 8;
        state ^= state >> 4;
        state ^= state >> 2;
        state ^= state >> 1;
        v0 = (v0 ^ state) & 1;
    }
    if (v0 != 0)
        return;
    // 3804
    for (s32 i = 0; i < 4; i++) {
        u32 state = g_sfmtParity[i];
        if (state != 0) {
            ctx->state[i] ^= (u32)0x80000000 >> __builtin_clz(state ^ (state - 1));
            return;
        }
        // 3830
    }
}

// 3.80+ for part2
// variant of mt19937 (SFMT)
s32 sfmtInit(SceKernelUtilsMt19937Context *ctx, u32 *seed, u32 seedSize) // 0x040038A8 in 3.80 part2
{
    u32 *end = &ctx->state[624];
    ctx->count = 624;
    // 38D8
    for (s32 i = 0; i < 624; i++) {
        ctx->state[i] = 0x8B8B8B8B;
    }
    s32 a3 = max(seedSize + 1, 624) - 1;
    u32 t0 = 0;
    u32 *state1 = &ctx->state[0];
    u32 *state2 = &ctx->state[306];
    u32 *state3 = &ctx->state[623];
    u32 *state4 = &ctx->state[317];
    // 3914
    for (s32 t1 = -1; t1 < a3; t1++) {
        u32 t6 = *state1 ^ *state2 ^ *state3;
        t6 = (t6 ^ (t6 >> 27)) * 0x19660D;
        *state2 += t6;
        if (seed != NULL) {
            if (t0 == 0) {
                t6 += seedSize;
            } else {
                t6 += *(seed++);
                if (t1 + 1 == seedSize)
                    seed = NULL;
            }
        }
        // 396C
        t6 += t0;
        *state4 += t6;
        *state1 = t6;
        t0 = t0 + 1;
        if (t0 >= 624)
            t0 = 0;
        if (++state1 == end)
            state1 = ctx->state;
        if (++state2 == end)
            state2 = ctx->state;
        if (++state3 == end)
            state3 = ctx->state;
        if (++state4 == end)
            state4 = ctx->state;
    }
    // 39D0
    for (s32 i = 0; i < 624; i++) {
        u32 t6 = *state1 + *state2 + *state3;
        t6 = (t6 ^ (t6 >> 27)) * 0x5D588B65;
        *state2 ^= t6;
        t6 = t6 - t0;
        *state4 ^= t6;
        *state1 = t6;
        t0 = t0 + 1;
        if (t0 >= 624)
            t0 = 0;
        if (++state1 == end)
            state1 = ctx->state;
        if (++state2 == end)
            state2 = ctx->state;
        if (++state3 == end)
            state3 = ctx->state;
        if (++state4 == end)
            state4 = ctx->state;
    }
    sfmtCertify(ctx);
    return 0;
}

void decrypt(void *preipl, u32 preiplSize, void *unk1, void *unk2, void *encryptedImg, s32 encryptedSize) // at 0x040F0D70  in 2.60
{
    SceKernelUtilsMt19937Context ctx; // sp..sp+2500
    u32 hash[8]; // sp + 2512
    u32 buf1[16]; // sp + 2544
    u32 buf2[8]; // sp + 2608
    if (g_usePrecomp) {
        memcpy(hash, g_precompKey.data(), 32);
    } else {
        scrambleBuf((u8*)unk1, 64, (u8*)preipl, preiplSize, (u8*)hash);
        if (preipl != NULL && debug) {
            printf("using hash = {0x%08x, {", *(u32*)unk1);
            for (s32 i = 0; i < 8; i++) {
                printf("0x%08x", hash[i]);
                if (i < 7) {
                    printf(", ");
                }
            }
            printf("}}\n");
        }
    }
    ctx.count = 0;
    if (g_useSfmt) {
        sfmtInit(&ctx, hash, g_customSha ? 7 : 8);
    } else {
        // 0DCC
        for (s32 i = 0; i < 624; i += 8) {
            memcpy(&ctx.state[i], hash, g_customSha ? 28 : 32);
            if (g_customSha) {
                ctx.state[i + 7] = 0;
            }
        }
    }
    memset(hash, 0, sizeof(hash));
    if (!g_useSfmt) {
        // 0E40
        for (s32 i = 0; i < 624; i++) {
            mt19937UInt(&ctx);
        }
    }
    u8 *decryptBuf = (u8*)encryptedImg;
    // 0E68
    for (s32 i = 0; i < encryptedSize; i += g_customSha ? 28 : 32) {
        if (g_useSfmt) {
            for (s32 j = 0; j < 16; j++) {
                buf1[j] = sfmtUInt(&ctx);
            }
        } else {
            // 0E6C
            for (s32 i = 0; i < 16; i++) {
                buf1[i] = mt19937UInt(&ctx);
            }
            if (g_emptyRound) {
                mt19937UInt(&ctx); // version 3.1x only
            }
        }
        scrambleBuf((u8*)unk2, 64, (u8*)buf1, 64, (u8*)buf2);
        s32 hashSize = g_customSha ? 28 : 32;
        if (i + hashSize > encryptedSize) {
            for (s32 j = 0; i + j < encryptedSize; j++) {
                *(decryptBuf++) ^= ((u8*)buf2)[j];
            }
        } else {
            for (s32 j = 0; j < hashSize / 4; j++) {
                *(u32*)decryptBuf ^= buf2[j];
                decryptBuf += 4;
            }
        }
    }
    // in 3.30+, here ctx, buf1 and buf2 are memset to 0
}

#ifdef PREIPL
// for 3.30+ part1
void decrypt330(void *preipl, u32 preiplSize, void *unk1, void *unk2, void *encryptedImg, s32 encryptedSize) // at 0x040F1018 in 3.30 part1
{
    // stack size: 6656
    u8 buf1[32]; // sp
    SceKernelUtilsMt19937Context ctx; // sp + 32..sp+2532
    u32 buf2[1024]; // sp+2544
    //u32 *alignedPreipl = (u32*)(preipl & 0xFFFFFF00); // we're not sure if our preipl buffer is aligned here
    u32 *alignedPreipl = (u32*)preipl;
    memset(buf1, 0, 32); // in 3.80+ only
    //mt19937Init(&ctx, (u32)preipl); // we want to use the actual memory address of the preipl, not the address on the host
    mt19937Init(&ctx, 0xBFC00040);
    // 107C
    for (s32 i = 0; i < PREIPL_SIZE / 4; i++) {
        buf2[i] = alignedPreipl[i] + mt19937UInt(&ctx);
    }
    scrambleBuf(g_newKey, preiplSize, (u8*)buf2, PREIPL_SIZE, buf1);
    memset(buf2, 0, 4096);
    memset(&ctx, 0, 2500);
    u8 checksum = 0;
    // 10F0
    for (s32 i = 0; i < 32; i++) {
        checksum = (checksum + buf1[i]) & 0xFF;
    }
    if (debug) {
        printf("checksum %02x vs %02x\n", g_checksum, checksum);
    }
    if (g_checksum == checksum) {
        // 1164
        // 1170
        for (s32 i = 0; i < 32; i++) {
            buf1[i] ^= g_xorKey[i];
        }
    }
    // 111C
    decrypt(buf1, 32, unk1, unk2, encryptedImg, encryptedSize);
}
#endif

s32 sha256Digest(u8 *data, u32 size, u8 *digest) // at 0x040F12CC 
{
    SHA256_CTX ctx;
    SHA256_Init2(&ctx);
    SHA256_Update(&ctx, data, size);
    SHA256_Final2(digest, &ctx);
    return 0;
}

int pspDecryptIPL3(const u8* pbIn, u8* pbOut, int cbIn)
{
    int ret;

    // all together now (pbIn/pbOut must be aligned)
    memcpy(pbOut+0x40, pbIn, cbIn);
    ret = sceUtilsBufferCopyWithRange(pbOut, cbIn+0x40, pbOut+0x40, cbIn, 1);
    if (ret != 0)
    {
        return 0;
    }

    ret = *(u32*)&pbIn[0x70];  // true size

    return ret;
}

// Decompress/unscramble IPL stages 2 & 3 and kernel keys
int decryptIPL(u8 *inData, u32 inDataSize, int version, u32 loadAddr, const char *filename)
{
    if (debug) {
        printf("Version %d\n", version);
    }
    g_customSha = g_useSfmt = g_emptyRound = g_usePrecomp = 0;

    kirk_init();

    u8 decBuf[1000000];
    u8 outBuf[1000000];

    // Values which seem to be constant throughout the IPL versions
    u32 img2_addr = 0x04100000;
    u32 kernelKeys_addr = 0x040FFF00;
    u32 part2LoadAddr = 0x04000000;

    char szDataPath[128];

    /////////////////////////
    // Version < 2.60: no scrambling, just decompress stage2 & decrypt stage3
    /////////////////////////

    if (version < 260) {
        for (u32 off = 0; off < 0x100; off += 4) {
            u32 gzip_hi = *(u32*)(inData + off);
            u32 gzip_lo = *(u32*)(inData + off + 4);
            if (gzip_hi >> 16 == 0x3C06 && gzip_lo >> 16 == 0x24C6) { // lui $a2, x & addiu $a2, $a2, x
                u32 gzip_addr = (gzip_hi << 16) + (s16)(gzip_lo & 0xFFFF);
                if (debug) {
                    printf("Decompressing zip at %08x\n", gzip_addr);
                }
                u32 realInSize;

                int decSize = gunzip((u8*)inData+gzip_addr-loadAddr, 0xE0000, decBuf, sizeof(decBuf), &realInSize);
                if (decSize < 0) {
                    printf("Failed decompressing stage2!\n");
                    return 1;
                }
                if (debug) {
                    printf("decompressed %d bytes\n", decSize);
                }
                sprintf(szDataPath, "./F0/PSARDUMPER/stage2_%s.gz", filename);
                WriteFile(szDataPath, (u8*)inData+gzip_addr-loadAddr, realInSize);

                sprintf(szDataPath, "./F0/PSARDUMPER/stage2_%s", filename);
                WriteFile(szDataPath, decBuf, decSize);
                printf(",stage2 decompressed");
                decSize = pspDecryptIPL3((u8*)inData+img2_addr-loadAddr, outBuf, inDataSize - (img2_addr-loadAddr));
                if (!decSize) {
                    printf("Failed decrypting stage3!\n");
                } else {
                    printf(",stage3 decrypted");
                    sprintf(szDataPath, "./F0/PSARDUMPER/stage3_%s", filename);
                    WriteFile(szDataPath, outBuf, decSize);
                    if (debug) {
                        printf("decrypted %d bytes\n", decSize);
                    }
                }
                return 0;
            }
        }
        printf("stage2 not found!?");
        return 1;
    }

    /////////////////////////
    // Get the main keys used for unscrambling
    /////////////////////////

    u32 key1_off = 0, key2_off = 0, img_off = 0, img_size = 0;
    // scan the binary for offsets
    for (u32 off = 0; off < 0x100; off += 4) {
        u32 curInstr = *(u32*)(inData + off);
        if (curInstr >> 16 == 0x3C06) { // lui $a2, x
            key1_off = curInstr << 16;
        }
        if (curInstr >> 16 == 0x24C6) { // addiu $a2, $a2, x
            key1_off += (s16)(curInstr & 0xFFFF);
        }
        if (curInstr >> 16 == 0x3C07) { // lui $a3, x
            key2_off = curInstr << 16;
        }
        if (curInstr >> 16 == 0x24E7) { // addiu $a3, $a3, x
            key2_off += (s16)(curInstr & 0xFFFF);
        }
        if (curInstr >> 16 == 0x3C08) { // lui $t0, x
            img_off = curInstr << 16;
        }
        if (curInstr >> 16 == 0x2508) { // addiu $t0, $t0, x
            img_off += (s16)(curInstr & 0xFFFF);
        }
        if (curInstr >> 16 == 0x3C09) { // lui $t1, x
            img_size = curInstr << 16;
        }
        if (curInstr >> 16 == 0x2529) { // addiu $t1, $t1, x
            img_size += (s16)(curInstr & 0xFFFF);
        }
        if (curInstr >> 26 == 0x03) { // jal
            break;
        }
    }
    if (version >= 310) {
        g_emptyRound = 1;
    }
    if (version >= 380) {
        g_customSha = 1;
    }
    if (version >= 505) {
        g_useSfmt = 1;
    }
    if (debug) {
        printf("keys at %08x, %08x, img at %08x, size %08x\n", key1_off, key2_off, img_off, img_size);
    }
    if (key1_off == 0 || key2_off == 0 || img_off == 0 || img_size == 0) {
        printf("One offset or size is not found, abort!\n");
        return 1;
    }

    /////////////////////////
    // Additional key/xor key/checksum for 3.30+ (for handling other pre-ipls?)
    /////////////////////////

    if (version >= 330) {
        for (u32 off = 0; off < img_off; off += 4) {
            u32 curInstr = *(u32*)(inData + off);
            if (curInstr == 0x27BDE5D0) { // addiu      $sp, $sp, -6704
                u32 loadInstr_hi = 0, loadInstr_lo = 0;
                for (u32 off2 = off; off2 < off + 0x100; off2 += 4) {
                    u32 curInstr2 = *(u32*)(inData + off2);
                    if (curInstr2 >> 16 == 0x3C07) { // lui $a3, x
                        loadInstr_hi = curInstr2;
                    }
                    if (curInstr2 >> 16 == 0x24E4) { // addiu $a0, $a3, x
                        loadInstr_lo = curInstr2;
                    }
                }
                if (loadInstr_hi == 0 || loadInstr_lo == 0) {
                    printf("Couldn't find key part2 for 3.30+\n");
                    return 1;
                }

                s16 addrLo = loadInstr_lo & 0xFFFF;
                u32 addr = (loadInstr_hi << 16) + addrLo;
                g_newKey = (u8*)inData+addr-loadAddr;
                g_xorKey = (u8*)inData+addr-loadAddr+0x300;
                g_checksum = inData[addr-loadAddr+0x320];
                if (debug) {
                    printf("key2 is %08x, %08x, %02x\n", addr, addr+0x300, g_checksum);
                }
                break;
            }
        }
    }

    /////////////////////////
    // Do the actual decryption & decompression of stage2
    /////////////////////////
    u32 key_idx = *(u32*)(inData+key1_off-loadAddr);
    auto precompKeyIt = g_keys.find(key_idx);
    if (precompKeyIt != g_keys.end()) {
        if (debug) {
            printf("found key %08x %08x...\n", precompKeyIt->second[0], precompKeyIt->second[1]);
        }
        g_usePrecomp = 1;
        g_precompKey = precompKeyIt->second;
        decrypt(NULL, 0, inData+key1_off-loadAddr, inData+key2_off-loadAddr, inData+img_off-loadAddr, img_size); // decrypt function
    } else {
#ifdef PREIPL
        if (version >= 330) {
            decrypt330(preipl_bin, 640, inData+key1_off-loadAddr, inData+key2_off-loadAddr, inData+img_off-loadAddr, img_size); // decrypt function // 3.30+
        } else {
            decrypt(preipl_bin + 0x40, 640, inData+key1_off-loadAddr, inData+key2_off-loadAddr, inData+img_off-loadAddr, img_size); // decrypt function
        }
#else
        if (debug) {
            printf("No preipl provided and key not found, aborting\n");
        }
        printf(",no key found");
        return 1;
#endif
    }
    g_usePrecomp = 0;

    u32 realInSize;

    int decSize = gunzip((u8*)inData+img_off-loadAddr, 0xE0000, decBuf, sizeof(decBuf), &realInSize);
    if (decSize < 0) {
        printf("Failed unscrambling or decompressing stage2!\n");
        return 1;
    }
    if (debug) {
        printf("decompressed %d bytes\n", decSize);
    }
    sprintf(szDataPath, "./F0/PSARDUMPER/stage2_%s.gz", filename);
    WriteFile(szDataPath, (u8*)inData+img_off-loadAddr, realInSize);

    sprintf(szDataPath, "./F0/PSARDUMPER/stage2_%s", filename);
    WriteFile(szDataPath, decBuf, decSize);
    printf(",stage2 unscrambled & decompressed");

    /////////////////////////
    // Find keys used for stage3 unscrambling (they're in stage2)
    /////////////////////////

    u32 key3_addr, key4_addr, img2_size;
    if (version < 280) {
        u32 load1_hi = *(u32*)(decBuf + 0x000C); // lui $v0, x
        u32 load1_lo = *(u32*)(decBuf + 0x0018); // addiu $a2, $v0, x
        u32 load2_hi = *(u32*)(decBuf + 0x001C); // lui $v0, x
        u32 load2_lo = *(u32*)(decBuf + 0x0040); // addiu $a3, $v0, x
        u32 load_size = *(u32*)(decBuf + 0x0028); // li $t1, x
        if (load1_hi >> 16 == 0x3C02 && load1_lo >> 16 == 0x2446 &&
            load2_hi >> 16 == 0x3C02 && load2_lo >> 16 == 0x2447 &&
            load_size >> 16 == 0x3409) {
            key3_addr = (load1_hi << 16) + (s16)(load1_lo & 0xFFFF);
            key4_addr = (load2_hi << 16) + (s16)(load2_lo & 0xFFFF);
            img2_size = load_size & 0xFFFF;
        } else {
            printf("Key2 not found!?\n");
            return 1;
        }
    } else {
        bool found = false;
        for (u32 off = 0; off < 0x400; off += 4) {
            u32 load1_hi = *(u32*)(decBuf + off + 0x0C); // lui $v0, x
            u32 load1_lo = *(u32*)(decBuf + off + 0x1C); // addiu $s0, $v0, x
            u32 load2_hi = *(u32*)(decBuf + off + 0x08); // lui $v1, x
            u32 load2_lo = *(u32*)(decBuf + off + 0x14); // addiu $s1, $v1, x
            u32 load_size = *(u32*)(decBuf + off + 0x28); // li $t1, x
            if (load1_hi >> 16 == 0x3C02 && load1_lo >> 16 == 0x2450 &&
                load2_hi >> 16 == 0x3C03 && load2_lo >> 16 == 0x2471 &&
                load_size >> 16 == 0x3409) {
                key3_addr = (load1_hi << 16) + (s16)(load1_lo & 0xFFFF);
                key4_addr = (load2_hi << 16) + (s16)(load2_lo & 0xFFFF);
                img2_size = load_size & 0xFFFF;
                found = true;
                break;
            }
            load1_hi = *(u32*)(decBuf + off + 0x10);
            load1_lo = *(u32*)(decBuf + off + 0x18);
            load2_hi = *(u32*)(decBuf + off + 0x04);
            load2_lo = *(u32*)(decBuf + off + 0x0C);
            load_size = *(u32*)(decBuf + off + 0x24);
            if (load1_hi >> 16 == 0x3C02 && load1_lo >> 16 == 0x2450 &&
                load2_hi >> 16 == 0x3C02 && load2_lo >> 16 == 0x2451 &&
                load_size >> 16 == 0x3409) {
                key3_addr = (load1_hi << 16) + (s16)(load1_lo & 0xFFFF);
                key4_addr = (load2_hi << 16) + (s16)(load2_lo & 0xFFFF);
                img2_size = load_size & 0xFFFF;
                found = true;
                break;
            }
        }
        if (!found) {
            printf("Unsupported version!\n");
            return 1;
        }
    }
    if (debug) {
        printf("part2 key offs %08x, %08x, size %08x, img2 at %08x\n", key3_addr, key4_addr, img2_size, img2_addr);
    }

    /////////////////////////
    // Find the keys used for kernel keys decryption (used by memlmd)
    /////////////////////////

    u32 key5_addr = 0, key6_addr = 0;
    if (version >= 330) {
        u32 load1_hi = *(u32*)(decBuf + 0x18);
        u32 load1_lo = *(u32*)(decBuf + 0x20);
        u32 load2_hi = *(u32*)(decBuf + 0x0c);
        u32 load2_lo = *(u32*)(decBuf + 0x14);
        if (load1_hi >> 16 == 0x3C02 && load1_lo >> 16 == 0x2450 &&
            load2_hi >> 16 == 0x3C02 && load2_lo >> 16 == 0x2451) {
            key5_addr = (load1_hi << 16) + (s16)(load1_lo & 0xFFFF);
            key6_addr = (load2_hi << 16) + (s16)(load2_lo & 0xFFFF);
        }
    }

    /////////////////////////
    // Decrypt the kernel keys
    /////////////////////////

    g_customSha = 0;
    if (version >= 380) {
        g_useSfmt = 1;
    }
    if (key5_addr != 0 && key6_addr != 0) {
        if (debug) {
            printf("decrypting kernel key at %08x using keys at %08x, %08x\n", kernelKeys_addr, key5_addr, key6_addr);
        }
        decrypt(NULL, 0, decBuf+key5_addr-part2LoadAddr, decBuf+key6_addr-part2LoadAddr, inData+kernelKeys_addr-loadAddr, 256);
        decSize = pspDecryptIPL3((u8*)inData+kernelKeys_addr-loadAddr, outBuf, 256);
        if (!decSize) {
            printf("Failed decrypting kernel keys!\n");
        } else {
            printf(",kernel keys decrypted");
            sprintf(szDataPath, "./F0/PSARDUMPER/kkeys_%s", filename);
            WriteFile(szDataPath, inData+kernelKeys_addr-loadAddr, decSize);
        }
    }

    /////////////////////////
    // Decrypt, and possibly decompress stage3
    /////////////////////////
    decrypt(NULL, 0, decBuf+key3_addr-part2LoadAddr, decBuf+key4_addr-part2LoadAddr, inData+img2_addr-loadAddr, img2_size);
    decSize = pspDecryptIPL3((u8*)inData+img2_addr-loadAddr, outBuf, inDataSize - (img2_addr-loadAddr));
    if (!decSize) {
        printf("Failed decrypting stage3!\n");
    } else {
        if (debug) {
            printf("decrypted %d bytes\n", decSize);
        }
        if (outBuf[0] == 0x1f && outBuf[1] == 0x8b) {
            u32 realInSize;
            int decompSize = gunzip(outBuf, decSize, decBuf, sizeof(decBuf), &realInSize);
            if (decompSize < 0) {
                printf("Failed decompressing stage3!\n");
                return 1;
            }
            if (debug) {
                printf("decompressed %d bytes\n", decompSize);
            }
            sprintf(szDataPath, "./F0/PSARDUMPER/stage3_%s.gz", filename);
            WriteFile(szDataPath, outBuf, realInSize);

            sprintf(szDataPath, "./F0/PSARDUMPER/stage3_%s", filename);
            WriteFile(szDataPath, decBuf, decompSize);
            printf(",stage3 decrypted & decompressed");
        } else {
            printf(",stage3 decrypted");
            sprintf(szDataPath, "./F0/PSARDUMPER/stage3_%s", filename);
            WriteFile(szDataPath, outBuf, decSize);
        }
    }

    return 0;
}

