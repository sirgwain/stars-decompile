#ifndef MSG_H_
#define MSG_H_

#include "strings.h"
#include "types.h"

/* globals */
extern char    aMSGCmpr[22836];      /* MEMORY_MSG:0x0000 */
extern uint8_t acMSG[387];           /* MEMORY_MSG:0x5934 */
extern int16_t aiMSGChunkOffset[7];  /* MEMORY_MSG:0x5ab8 */
extern char    rgMSGLookupTable[72]; /* MEMORY_MSG:0x5ac6 */
extern char    rgcMsgArgs[387];      /* MEMORY_MSG:0x5b0e */

/* functions */
int16_t FFindPlayerMessage(int16_t iPlr, int16_t iMsg, int16_t iObj); /* MEMORY_MSG:0x932a */
int16_t FGetNMsgbig(int16_t iMsg, MSGBIG *pmb);                       /* MEMORY_MSG:0x8444 */
int16_t PackageUpMsg(uint8_t *pb, int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6,
                     int16_t p7);                                                                 /* MEMORY_MSG:0x802a */
char   *PszGetMessageN(int16_t iMsg);                                                             /* MEMORY_MSG:0x8580 */
int16_t IdmGetMessageN(int16_t iMsg);                                                             /* MEMORY_MSG:0x8412 */
int16_t FFinishPlrMsgEntry(int16_t dInc);                                                         /* MEMORY_MSG:0x9bd6 */
void    MarkPlanetsPlayerLost(int16_t iPlayer);                                                   /* MEMORY_MSG:0x93c6 */
char   *PszFormatMessage(MessageId idm, int16_t *pParams);                                        /* MEMORY_MSG:0x9220 */
int16_t FSendPlrMsg2XGen(int16_t fPrepend, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2); /* MEMORY_MSG:0x823a */
void    SetFilteringGroups(MessageId idm, int16_t fSet);                                          /* MEMORY_MSG:0xa018 */
int16_t FSendPlrMsg2(int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2);         /* MEMORY_MSG:0x7eaa */
void    ReadPlayerMessages(void);                                                                 /* MEMORY_MSG:0x994a */
int16_t FSendPrependedPlrMsg(int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6,
                             int16_t p7);                                 /* MEMORY_MSG:0x7f80 */
void    MarkPlayersThatSentMsgs(int16_t iPlayer);                         /* MEMORY_MSG:0x9604 */
void    ResetMessages(void);                                              /* MEMORY_MSG:0x98d6 */
int16_t FRemovePlayerMessage(int16_t iPlr, MessageId iMsg, int16_t iObj); /* MEMORY_MSG:0x9278 */
char   *PszFormatString(char *pszFormat, int16_t *pParamsReal);           /* MEMORY_MSG:0x85cc */
char   *PszGetCompressedMessage(MessageId idm);                           /* MEMORY_MSG:0x9eb8 */
void    WritePlayerMessages(int16_t iPlayer);                             /* MEMORY_MSG:0x9702 */
int16_t IMsgPrev(int16_t fFilteredOnly);                                  /* MEMORY_MSG:0x78d8 */
int16_t IMsgNext(int16_t fFilteredOnly);                                  /* MEMORY_MSG:0x7808 */
char   *PszFormatIds(StringId ids, int16_t *pParams);                     /* MEMORY_MSG:0x924c */
int16_t FSendPlrMsg(int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6,
                    int16_t p7); /* MEMORY_MSG:0x7ee8 */

#ifdef _WIN32

void             DecorateMsgTitleBar(HDC hdc, RECT *prc);                                        /* MEMORY_MSG:0x799c */
int16_t          HtMsgBox(POINT pt);                                                             /* MEMORY_MSG:0x7d8c */
void             SetMsgTitle(HWND hwnd);                                                         /* MEMORY_MSG:0x7218 */
INT_PTR CALLBACK MsgDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */         /* MEMORY_MSG:0x8f68 */
LRESULT CALLBACK MessageWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* PASCAL */ /* MEMORY_MSG:0x5c92 */

#endif /* _WIN32 */

#endif /* MSG_H_ */
