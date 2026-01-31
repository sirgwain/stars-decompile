
#include "types.h"

#include "globals.h"
#include "tutor2.h"

/* globals */
char    aTUTCmpr[22323] = {0};
uint8_t acTUT[640] = {0};
int16_t aiTUTChunkOffset[10] = {0};
char    rgTUTLookupTable[76] = {0};

extern const char *const aTUTUncompressed[];

/* functions */
int16_t CchTutorString(char *pchOut, int16_t idt) {

    char *dst0 = pchOut;

    if (iLastTutGet == idt) {
        return strlen(pchOut);
    }
    const char *src = aTUTUncompressed[idt];

    while (*src != '\0') {
        *pchOut++ = *src++;
    }
    *pchOut = '\0';

    /* number of chars copied (not including the NUL) */
    return (int16_t)(pchOut - dst0);
}
