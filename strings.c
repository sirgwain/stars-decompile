
#include "types.h"

#include "strings.h"

/* globals */
char aSTRCmpr[28209];  /* MEMORY_STRINGS:0x0000 */
uint8_t acSTR[1414];  /* MEMORY_STRINGS:0x6e32 */
int16_t aiSTRChunkOffset[23];  /* MEMORY_STRINGS:0x73b8 */
char rgSTRLookupTable[84];  /* MEMORY_STRINGS:0x73e6 */

/* functions */
char * PszGetCompressedString(int16_t ids)
{
    int16_t iChunk;
    char *pchLen;
    int16_t iBuild;
    int16_t iNibble;
    int16_t i;
    int16_t iLen;
    char *pch;
    char *pszOut;
    int16_t iOffset;
    int16_t fHigh;

    /* TODO: implement */
    return NULL;
}
