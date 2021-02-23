#ifndef __PSPDECRYPT_H__
#define __PSPDECRYPT_H__

#include <string>
#include "CommonTypes.h"

/**
 * Sign checks a buffer
 *
 * @param buf - The input/output buffer
 *
 * @returns 0 on success, < 0 on error
*/
int pspSignCheck(u8 *buf);

/**
 * Unsign checks a buffer
 *
 * @param buf - The input/output buffer
 *
 * @returns 0 on success, < 0 on error
*/
int pspUnsignCheck(u8 *buf);

/**
 * Checks if a ~PSP file is sign checked
 *
 * @param buf - The buffer 
 *
 * @returns 1 if signchecked, 0 otherwise
*/
int pspIsSignChecked(u8 *buf);

/**
 * Decrypts the first stage of IPL
 *
 * @param pbIn - The input buffer
 * @param pbOut - The output buffer that receives the decoded data
 * @param cbIn - The size of the encrypted data
 *
 * @returns the size of the decrypted data (= 0 on error)
*/
int pspDecryptIPL1(const u8* pbIn, u8* pbOut, int cbIn);

/**
 * Linearalizes the decrypted first stage of IPL
 *
 * @param pbIn - The input buffer
 * @param pbOut - The output buffer
 * @param cbIn - The size of input
 *
 * @returns the size of the linearalized data on success, 0 on error
*/
int pspLinearizeIPL2(const u8* pbIn, u8* pbOut, int cbIn, u32 *startAddr);

/**
 * Decrypts the IPL payload, only valid for 1.00-2.50 IPL
 *
 * @param pbIn - The input buffer containing the linearilized first stage
 * @param pbOut - The buffer that receives the decoded data
 * @param cbIn - The size of input
 * 
 * @returns the size of the decrypted payload on success, 0 on error
*/
int pspDecryptIPL3(const u8* pbIn, u8* pbOut, int cbIn);

int decryptIPL(u8 *inData, u32 inDataSize, int version, const char *filename, std::string outdir, u8 *preipl, u32 preiplSize, bool verbose);

/**
 * Checks if buffer is compressed
 *
 * @param buf - The buffer 
 *
 * @returns 1 if compressed, 0 otherwise
*/
int pspIsCompressed(u8 *buf);

/**
 * Decompresses a GZIP or 2RLZ data
 *
 * @param inbuf - The input buffer with the compressed data
 * @param outbuf - The output buffer that receives the decompressed data
 * @param outcapacity - The max capacity of the output buffer
 *
 * @returns the size of the decompressed data on success, < 0 on error
*/
int pspDecompress(u8 *inbuf, u32 insize, u8 *outbuf, u32 outcapacity);

/**
 * Decrypts a file table (3.70+)
 *
 * @param buf1 - The input/output buffer
 * @param buf2 - Buffer for temporal use by the decoder
 * @param size - The size of input
 * @param mode - The mode
 *
 * @returns the size of the decrypted table on success, < 0 on error
*/
int pspDecryptTable(u8 *buf1, u8 *buf2, int size, int mode);


#endif

