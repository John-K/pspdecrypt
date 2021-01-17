#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;

#define max(a, b) ((a) < (b) ? (b) : (a))

int read_bit(u32 *inputVal, u32 *range, u8 *probPtr, u8 **inBuf, u32 decay, u32 bonus)
{
    u32 bound;
    u8 prob = *probPtr;
    if ((*range >> 24) == 0) {
        *inputVal = (*inputVal << 8) + *((*inBuf)++);
        bound = *range * prob;
        *range <<= 8;
    } else {
        bound = (*range >> 8) * prob;
    }
    prob -= (prob >> decay);
    if (*inputVal >= bound) {
        *inputVal -= bound;
        *range -= bound;
        *probPtr = prob;
        return 0;
    } else {
        *range = bound;
        *probPtr = prob + bonus;
        return 1;
    }
}

int read_bit_uniform(u32 *inputVal, u32 *range, u8 **inBuf)
{
    if (*range >> 24 == 0) {
        *inputVal = (*inputVal << 8) + *((*inBuf)++);
        *range = *range << 7;
    } else {
        *range = *range >> 1;
    }
    if (*inputVal >= *range) {
        *inputVal -= *range;
        return 0;
    } else {
        return 1;
    }
}

int read_bit_uniform_nonormal(u32 *inputVal, u32 *range)
{
    *range >>= 1;
    if (*inputVal >= *range) {
        *inputVal -= *range;
        return 0;
    } else {
        return 1;
    }
}

void output_raw(u32 *inputVal, u32 *range, u8 *probs, u8 **inBuf, u32 *curByte, u8 *curOut, u8 shift)
{
    u32 mask = (((size_t)curOut & 7) << 8) | (*curByte & 0xFF);
    u8 *curProbs = &probs[((mask >> shift) & 7) * 255] - 1;
    *curByte = 1;
    while (*curByte < 0x100) {
        u8 *curProb = &curProbs[*curByte];
        *curByte <<= 1;
        if (read_bit(inputVal, range, curProb, inBuf, 3, 31)) {
            *curByte |= 1;
        }
    }
    *curOut = *curByte & 0xff;
    //printf("output raw %02x\n", *curByte & 0xff);
}

int decompress_kle(u8 *outBuf, int outSize, u8 *inBuf, void **end, int isKl4e)
{
    u8 litProbs[2040]; // sp..sp+2040 (excluded)
    u8 copyDistBitsProbs[304]; // sp+2040..sp+? (estimated size)
    u8 copyDistProbs[144]; // sp+2344..sp+? (estimated size)
    u8 copyCountBitsProbs[64]; // sp+2488..sp+2552
    u8 copyCountProbs[256]; // sp+2552..sp+? (estimated size)
    u8 *outEnd = outBuf + outSize;
    u8 *curOut = outBuf;
    u32 curByte = 0;
    u32 range = 0xffffffff;
    u32 copyDist, copyCount;
    u8 *curCopyDistBitsProbs;
    u32 inputVal = (inBuf[1] << 24) | (inBuf[2] << 16) | (inBuf[3] << 8) | inBuf[4];
    if (inBuf[0] & 0x80) {
        inBuf += 5;
        u8 *dataEnd = outBuf + inputVal;
        if (dataEnd >= outEnd) {
            return 0x80000104; // SCE_ERROR_INVALID_SIZE
        }
        while (curOut < dataEnd) {
            *(curOut++) = *(inBuf++);
        }
        inBuf--;
        if (end != NULL) {
            *end = inBuf;
        }
        return curOut - outBuf;
    }
    u8 byte = 128 - (((inBuf[0] >> 3) & 3) << 4);
    u8 shift = inBuf[0] & 0x7;
    memset(litProbs, byte, sizeof(litProbs));
    memset(copyCountBitsProbs, byte, sizeof(copyCountBitsProbs));
    memset(copyDistBitsProbs, byte, sizeof(copyDistBitsProbs));
    memset(copyCountProbs, byte, sizeof(copyCountProbs));
    memset(copyDistProbs, byte, sizeof(copyDistProbs));
    u8 *curCopyCountBitsProbs = copyCountBitsProbs;
    inBuf += 5;
    output_raw(&inputVal, &range, litProbs, &inBuf, &curByte, curOut, shift);
    while (1) {
        curOut++;
        if (read_bit(&inputVal, &range, curCopyCountBitsProbs, &inBuf, 4, 15) == 0) {
            curCopyCountBitsProbs = max(curCopyCountBitsProbs - 1, copyCountBitsProbs);
            if (curOut == outEnd) {
                return 0x80000104; // SCE_ERROR_INVALID_SIZE
            }
            output_raw(&inputVal, &range, litProbs, &inBuf, &curByte, curOut, shift);
            continue;
        }
        copyCount = 1;
        s32 copyCountBits = -1;
        while (copyCountBits < 6) {
            curCopyCountBitsProbs += 8;
            if (!read_bit(&inputVal, &range, curCopyCountBitsProbs, &inBuf, 4, 15)) {
                break;
            }
            copyCountBits++;
        }
        s32 powLimit;
        if (copyCountBits >= 0) {
            u8 *probs = &copyCountProbs[(copyCountBits << 5) | ((((size_t)curOut & 3) << (copyCountBits + 3)) & 0x18) | ((size_t)curCopyCountBitsProbs & 7)];
            if (copyCountBits < 3) {
                copyCount = 1;
            } else {
                copyCount = 2 + read_bit(&inputVal, &range, probs + 24, &inBuf, 3, 31);
                if (copyCountBits > 3) {
                    copyCount = (copyCount << 1) | read_bit(&inputVal, &range, probs + 24, &inBuf, 3, 31);
                    if (copyCountBits > 4) {
                        copyCount = (copyCount << 1) | read_bit_uniform(&inputVal, &range, &inBuf);
                    }
                    for (u32 i = 5; i < copyCountBits; i++) {
                        copyCount = (copyCount << 1) | read_bit_uniform_nonormal(&inputVal, &range);
                    }
                }
            }
            copyCount = copyCount << 1;
            if (read_bit(&inputVal, &range, probs, &inBuf, 3, 31)) {
                copyCount |= 1;
                if (copyCountBits <= 0) {
                    powLimit = isKl4e ? 256 : 128;
                    curCopyDistBitsProbs = &copyDistBitsProbs[56 + copyCountBits];
                }
            } else {
                if (copyCountBits <= 0) {
                    powLimit = 64;
                    curCopyDistBitsProbs = &copyDistBitsProbs[copyCountBits];
                }
            }
            if (copyCountBits > 0) {
                copyCount = (copyCount << 1) | read_bit(&inputVal, &range, probs + 8, &inBuf, 3, 31);
                if (copyCountBits != 1) {
                    copyCount = copyCount << 1;
                    if (read_bit(&inputVal, &range, probs + 16, &inBuf, 3, 31)) {
                        copyCount = copyCount + 1;
                        if (copyCount == 0xFF) {
                            if (end != NULL) {
                                *end = inBuf;
                            }
                            return curOut - outBuf;
                        }
                    }
                }
                curCopyDistBitsProbs = &copyDistBitsProbs[56 + copyCountBits];
                powLimit = isKl4e ? 256 : 128;
            }
        } else {
            powLimit = 64;
            curCopyDistBitsProbs = &copyDistBitsProbs[copyCountBits];
        }
        //printf("copyCount = %d\n", copyCount);
        s32 curPow = 8;
        int skip5 = 0;
        s32 copyDistBits;
        while (1) {
            u8 *curProb = curCopyDistBitsProbs + (curPow - 7);
            curPow <<= 1;
            copyDistBits = curPow - powLimit;
            if (!read_bit(&inputVal, &range, curProb, &inBuf, 3, 31)) {
                if (copyDistBits >= 0) {
                    if (copyDistBits != 0) {
                        copyDistBits -= 8;
                        break;
                    }
                    copyDist = 0;
                    if (curCopyDistBitsProbs == curOut) { // Is this a mistake by Sony?
                        //printf("???\n");
                        return 0x80000108; // SCE_ERROR_INVALID_FORMAT
                    }
                    skip5 = 1;
                    break;
                }
            } else {
                curPow += 8;
                if (copyDistBits >= 0)
                    break;
            }
        }
        if (!skip5) {
            u8 *curProbs = &copyDistProbs[copyDistBits];
            s32 readBits = copyDistBits / 8;
            if (readBits < 3) {
                copyDist = 1;
            } else {
                copyDist = 2 + read_bit(&inputVal, &range, curProbs + 3, &inBuf, 3, 31);
                if (readBits > 3) {
                    copyDist = (copyDist << 1) | read_bit(&inputVal, &range, curProbs + 3, &inBuf, 3, 31);
                    if (readBits > 4) {
                        copyDist = (copyDist << 1) | read_bit_uniform(&inputVal, &range, &inBuf);
                        readBits--;
                    }
                    while (readBits > 4) {
                        copyDist = copyDist << 1;
                        copyDist += read_bit_uniform_nonormal(&inputVal, &range);
                        readBits--;
                    }
                }
            }
            copyDist = copyDist << 1;
            if (read_bit(&inputVal, &range, curProbs, &inBuf, 3, 31)) {
                if (readBits > 0) {
                    copyDist = copyDist + 1;
                }
            } else {
                if (readBits <= 0) {
                    copyDist = copyDist - 1;
                }
            }
            if (readBits > 0) {
                copyDist = copyDist << 1;
                if (read_bit(&inputVal, &range, curProbs + 1, &inBuf, 3, 31)) {
                    if (readBits != 1) {
                        copyDist = copyDist + 1;
                    }
                } else {
                    if (readBits == 1) {
                        copyDist = copyDist - 1;
                    }
                }
                if (readBits != 1) {
                    copyDist = copyDist << 1;
                    if (!read_bit(&inputVal, &range, curProbs + 2, &inBuf, 3, 31)) {
                        copyDist = copyDist - 1;
                    }
                }
            }
            if (copyDist >= curOut - outBuf) {
                //printf("copy distance is too big!\n");
                return 0x80000108; // SCE_ERROR_INVALID_FORMAT
            }
        }
        //printf("count=%d dist=%d\n", copyCount, copyDist);
        for (u32 i = 0; i < copyCount + 1; i++) {
            curOut[i] = (curOut - copyDist - 1)[i];
            //printf("copy %02x\n", curOut[i]);
        }
        curByte = curOut[copyCount];
        curOut += copyCount;
        curCopyCountBitsProbs = &copyCountBitsProbs[6 + ((size_t)curOut & 1)];
    }
}
/*
void main(int argc, char *argv[]) {
    u8 *out = malloc(2000000);
    u8 *in = malloc(2000000);
    FILE *fin = fopen(argv[1], "r");
    int read = 0;
    int totalRead = 0;
    while ((read = fread(&in[totalRead], 1, 64, fin)) > 0) {
        totalRead += read;
    }
    fclose(fin);
    ////printf("read %d bytes\n");
    int outs = UtilsForKernel_6C6887EE(out, 2000000, in+4, NULL);
    //printf("-----> ret %08x\n", outs);
    FILE *fout = fopen("test", "w");
    fwrite(out, outs, 1, fout);
    fclose(fout);
}
*/
