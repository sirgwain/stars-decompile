
#include "types.h"

#include "tutor2.h"

/* globals */
char aTUTCmpr[22323];  /* MEMORY_TUTOR2:0x0000 */
uint8_t acTUT[640];  /* MEMORY_TUTOR2:0x5734 */
int16_t aiTUTChunkOffset[10];  /* MEMORY_TUTOR2:0x59b4 */
char rgTUTLookupTable[76];  /* MEMORY_TUTOR2:0x59c8 */

/* functions */
int16_t CchTutorString(char *pchOut, int16_t idt)
{
    int16_t iOffset;
    int16_t fHigh;
    int16_t iChunk;
    char *pchLen;
    int16_t iBuild;
    int16_t iNibble;
    int16_t i;
    char *pszOut;
    int16_t iLen;
    char *pch;

    /* TODO: implement */
    return 0;
}
