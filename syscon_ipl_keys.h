/* Function Delarations for handling 02g-11g BFC00210 Xor Keys with required syscon secrets
    by Proxima - 2021
*/

#pragma once

void getSysconIPLKey(int type, unsigned char * indata, unsigned char * outdata);
int findStage2Keys(unsigned char * stage2, int length);
