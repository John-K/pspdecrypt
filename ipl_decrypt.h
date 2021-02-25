#pragma once

int extractIPLStages(u8 *inData, u32 inDataSize, int version, u32 loadAddr, const char *filename, std::string outdir, u8 *preipl_bin, u32 preiplSize, bool verbose);

