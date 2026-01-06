#ifndef STRINGS_H_
#define STRINGS_H_


#include "types.h"

/* globals */
extern char aSTRCmpr[28209];  /* MEMORY_STRINGS:0x0000 */
extern uint8_t acSTR[1414];  /* MEMORY_STRINGS:0x6e32 */
extern int16_t aiSTRChunkOffset[23];  /* MEMORY_STRINGS:0x73b8 */
extern char rgSTRLookupTable[84];  /* MEMORY_STRINGS:0x73e6 */

/* functions */
char * PszGetCompressedString(int16_t);  /* MEMORY_STRINGS:0x743a */

#endif /* STRINGS_H_ */
