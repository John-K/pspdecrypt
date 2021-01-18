/*
 * KL4E decompression code, reverse engineered from the 6.60 firmware by artart78.
 * Original function: UtilsForKernel_6C6887EE from sysmem.prx.
 *
 * The original code is most likely written directly on assembly and quite obfuscated (which might just be
 * a consequence of heavy optimization). This code is a bit simplified on some points (replaced inlined copies
 * with memcpy, dropped optimized word-by-word copy, dropped a cache instruction) but should be functionally equivalent.
 * It was split into several functions for readability purposes, but corresponds to a single function.
 *
 * KL3E's assembly code is fairly different from KL4E's, but it was found out that just changing one constant made it
 * work on KL3E. There may be corner cases which are not handled since KL3E's function (sub_00000000 in loadexec)
 * was not reversed, and there are very likely files which it will decompress "successfully" although they should
 * give an error (for example, for copy-only not-compressed files).
 *
 * Many thanks to BenHur (see libLZR.h) and tpunix (see https://github.com/tpunix/kirk_engine/blob/master/npdpc/tlzrc.c)
 * for providing code of variants (2RLZ and LZRC?) which helped me a lot understand how the stuff works in general.
 */

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

/*
 * KL4E's behavior seems to be very similar to LZMA.
 *
 * It is based on two things:
 * 1) the LZ77 algorithm
 * 2) arithmetic coding.
 *
 * The first point is just the idea that, in order to compress a stream using repetitions, you can either:
 * - output a raw byte
 * - repeat a sequence of previous raw bytes.
 * In the base LZ77 algorithm, the main loop first reads a bit, then:
 * - if the bit is a 0, read the next 8 bits and output the byte which corresponds (called a literal),
 * - if the bit is a 1, read some distance m and length n which can be encoded in various ways, and copy
 *   the n bytes which were output m bytes earlier.
 *
 * Here, instead of encoding bits directly, KL4E uses some kind of arithmetic coding. The general idea is
 * that you read 4 bytes, then if you know a 1 will happen with probability p, you consider the output
 * is a 1 if the 4 bytes are in the [0, 2^32 * p] interval, and a 0 if it's in the [2 ^ 32 * p, 2 ^ 32]
 * interval. You then repeat the operation by taking the subinterval in which the value is, and read another
 * byte when the interval became smaller than 2^24. The probabilities are also updated each time, by decaying
 * (they're multiplied by 7/8 or 15/16 each time) and receiving an additional 31 or 15 if the output was indeed a 1.
 *
 * Compared to 2RLZ, here all the probabilities are set to a single value given by the header (instead of
 * just being 0x80 ie 1/2 by default), and a literal is output directly without checking if the first bit is 0.
 *
 * The rest is just up to how you encode distance and length codes, which is where the difference between KL3E
 * and KL4E lies (KL4E seems to be able to have bigger maximum "distance" codes), and also what probabilities
 * you consider (for example, Sony uses different probabilities depending on the file's offset modulo 8).
 */

/*
 * Read one bit using arithmetic coding, with a given (updated) probability and its associated decay/bonus.
 */
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

/*
 * Same as above, but with balanced probability 1/2.
 */
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

/*
 * Same as above, but without normalizing the range.
 */
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

/*
 * Output a raw byte by reading 8 bits using arithmetic coding.
 */
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
}

int decompress_kle(u8 *outBuf, int outSize, u8 *inBuf, void **end, int isKl4e)
{
    u8 litProbs[2040];
    u8 copyDistBitsProbs[304];
    u8 copyDistProbs[144];
    u8 copyCountBitsProbs[64];
    u8 copyCountProbs[256];
    u8 *outEnd = outBuf + outSize;
    u8 *curOut = outBuf;
    u32 curByte = 0;
    u32 range = 0xffffffff;
    u32 copyDist, copyCount;
    u8 *curCopyDistBitsProbs;
    u32 inputVal = (inBuf[1] << 24) | (inBuf[2] << 16) | (inBuf[3] << 8) | inBuf[4];
    // Handle the direct copy case (if the file is actually not compressed).
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
    // Initialize probabilities from the header value.
    u8 byte = 128 - (((inBuf[0] >> 3) & 3) << 4);
    memset(litProbs, byte, sizeof(litProbs));
    memset(copyCountBitsProbs, byte, sizeof(copyCountBitsProbs));
    memset(copyDistBitsProbs, byte, sizeof(copyDistBitsProbs));
    memset(copyCountProbs, byte, sizeof(copyCountProbs));
    memset(copyDistProbs, byte, sizeof(copyDistProbs));
    u8 *curCopyCountBitsProbs = copyCountBitsProbs;
    /* Shift used to determine if the probabilities should be determined more by the
     * output's byte alignment or by the previous byte. */
    u8 shift = inBuf[0] & 0x7;
    inBuf += 5;
    // Read a literal directly.
    output_raw(&inputVal, &range, litProbs, &inBuf, &curByte, curOut, shift);
    while (1) {
        curOut++;
        // If we read a 0, read a literal.
        if (read_bit(&inputVal, &range, curCopyCountBitsProbs, &inBuf, 4, 15) == 0) {
            curCopyCountBitsProbs = max(curCopyCountBitsProbs - 1, copyCountBitsProbs);
            if (curOut == outEnd) {
                return 0x80000104; // SCE_ERROR_INVALID_SIZE
            }
            output_raw(&inputVal, &range, litProbs, &inBuf, &curByte, curOut, shift);
            continue;
        }
        // Otherwise, first find the number of bits used in the 'length' code.
        copyCount = 1;
        s32 copyCountBits = -1;
        while (copyCountBits < 6) {
            curCopyCountBitsProbs += 8;
            if (!read_bit(&inputVal, &range, curCopyCountBitsProbs, &inBuf, 4, 15)) {
                break;
            }
            copyCountBits++;
        }
        // Determine the length itself, and use different distance code probabilities depending on it (and on whether it's KL3E or KL4E).
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
        // Find out the number of bits used for distance codes.
        s32 curPow = 8;
        int skip = 0;
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
                        return 0x80000108; // SCE_ERROR_INVALID_FORMAT
                    }
                    skip = 1; // Just copy with a zero distance.
                    break;
                }
            } else {
                curPow += 8;
                if (copyDistBits >= 0)
                    break;
            }
        }
        if (!skip) {
            // Find out the distance itself.
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
                return 0x80000108; // SCE_ERROR_INVALID_FORMAT
            }
        }
        // Copy the bytes with the given count and distance
        for (u32 i = 0; i < copyCount + 1; i++) {
            curOut[i] = (curOut - copyDist - 1)[i];
        }
        curByte = curOut[copyCount];
        curOut += copyCount;
        curCopyCountBitsProbs = &copyCountBitsProbs[6 + ((size_t)curOut & 1)];
    }
}
