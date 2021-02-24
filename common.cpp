#include <fstream>
#include <zlib.h>

#include "CommonTypes.h"

int WriteFile(const char *file, void *buf, int size)
{
    std::fstream myfile;
    myfile = std::fstream(file, std::ios::out | std::ios::binary);
    myfile.write((char*)buf, size);
    myfile.close();
    return size;
}

s32 gunzip(u8 *inBuf, u32 inSize, u8 *outBuf, u32 outSize, u32 *realInSize, bool noHeader)
{
    if (!noHeader && (inBuf[0] != 0x1f || inBuf[1] != 0x8b)) {
        printf("Invalid gzip!\n");
        return -1;
    }
    z_stream infstream;
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;
    infstream.avail_in = inSize;
    infstream.next_in = inBuf;
    infstream.avail_out = outSize;
    infstream.next_out = outBuf;

    if (noHeader) {
        inflateInit(&infstream);
    } else {
        inflateInit2(&infstream, 16+MAX_WBITS);
    }
    int ret;
    ret = inflate(&infstream, Z_NO_FLUSH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        inflateEnd(&infstream);
        return -1;
    }
    inflateEnd(&infstream);
    if (realInSize != NULL) {
        *realInSize = infstream.total_in;
    }
    return infstream.total_out;
}

