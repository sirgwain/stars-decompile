#ifndef TUTOR2_H_
#define TUTOR2_H_


#include "types.h"

/* globals */
extern char aTUTCmpr[22323];  /* MEMORY_TUTOR2:0x0000 */
extern uint8_t acTUT[640];  /* MEMORY_TUTOR2:0x5734 */
extern int16_t aiTUTChunkOffset[10];  /* MEMORY_TUTOR2:0x59b4 */
extern char rgTUTLookupTable[76];  /* MEMORY_TUTOR2:0x59c8 */

/* functions */
int16_t CchTutorString(char *, int16_t);  /* MEMORY_TUTOR2:0x5a14 */

#endif /* TUTOR2_H_ */
