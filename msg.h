#ifndef MSG_H_
#define MSG_H_


#include "types.h"

/* globals */
extern char aMSGCmpr[22836];  /* MEMORY_MSG:0x0000 */
extern uint8_t acMSG[387];  /* MEMORY_MSG:0x5934 */
extern int16_t aiMSGChunkOffset[7];  /* MEMORY_MSG:0x5ab8 */
extern char rgMSGLookupTable[72];  /* MEMORY_MSG:0x5ac6 */
extern char rgcMsgArgs[387];  /* MEMORY_MSG:0x5b0e */

/* functions */
int16_t FFindPlayerMessage(int16_t, int16_t, int16_t);  /* MEMORY_MSG:0x932a */
int16_t FGetNMsgbig(int16_t, MSGBIG *);  /* MEMORY_MSG:0x8444 */
void DecorateMsgTitleBar(uint16_t, RECT *);  /* MEMORY_MSG:0x799c */
int16_t PackageUpMsg(uint8_t *, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t);  /* MEMORY_MSG:0x802a */
char * PszGetMessageN(int16_t);  /* MEMORY_MSG:0x8580 */
int16_t IdmGetMessageN(int16_t);  /* MEMORY_MSG:0x8412 */
int16_t FFinishPlrMsgEntry(int16_t);  /* MEMORY_MSG:0x9bd6 */
void SetMsgTitle(uint16_t);  /* MEMORY_MSG:0x7218 */
void MarkPlanetsPlayerLost(int16_t);  /* MEMORY_MSG:0x93c6 */
char * PszFormatMessage(int16_t, int16_t *);  /* MEMORY_MSG:0x9220 */
int16_t FSendPlrMsg2XGen(int16_t, int16_t, int16_t, int16_t, int16_t);  /* MEMORY_MSG:0x823a */
void SetFilteringGroups(int16_t, int16_t);  /* MEMORY_MSG:0xa018 */
int16_t FSendPlrMsg2(int16_t, int16_t, int16_t, int16_t, int16_t);  /* MEMORY_MSG:0x7eaa */
void ReadPlayerMessages(void);  /* MEMORY_MSG:0x994a */
int16_t FSendPrependedPlrMsg(int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t);  /* MEMORY_MSG:0x7f80 */
void MarkPlayersThatSentMsgs(int16_t);  /* MEMORY_MSG:0x9604 */
void ResetMessages(void);  /* MEMORY_MSG:0x98d6 */
int16_t FRemovePlayerMessage(int16_t, int16_t, int16_t);  /* MEMORY_MSG:0x9278 */
char * PszFormatString(char *, int16_t *);  /* MEMORY_MSG:0x85cc */
char * PszGetCompressedMessage(int16_t);  /* MEMORY_MSG:0x9eb8 */
int16_t MsgDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_MSG:0x8f68 */
void WritePlayerMessages(int16_t);  /* MEMORY_MSG:0x9702 */
int16_t HtMsgBox(POINT);  /* MEMORY_MSG:0x7d8c */
int16_t IMsgPrev(int16_t);  /* MEMORY_MSG:0x78d8 */
int16_t IMsgNext(int16_t);  /* MEMORY_MSG:0x7808 */
char * PszFormatIds(int16_t, int16_t *);  /* MEMORY_MSG:0x924c */
int16_t FSendPlrMsg(int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t);  /* MEMORY_MSG:0x7ee8 */
int32_t MessageWndProc(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_MSG:0x5c92 */

#endif /* MSG_H_ */
