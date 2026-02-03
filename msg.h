#ifndef MSG_H_
#define MSG_H_

#include "strings.h"
#include "types.h"

/* globals */
extern char    aMSGCmpr[22836];
extern uint8_t acMSG[387];
extern int16_t aiMSGChunkOffset[7];
extern char    rgMSGLookupTable[72];
extern char    rgcMsgArgs[387];

/* functions */
int16_t FFindPlayerMessage(int16_t iPlr, int16_t iMsg, int16_t iObj);
int16_t FGetNMsgbig(int16_t iMsg, MSGBIG *pmb);
int16_t PackageUpMsg(uint8_t *pb, int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6,
                     int16_t p7);
char   *PszGetMessageN(int16_t iMsg);
int16_t IdmGetMessageN(int16_t iMsg);
int16_t FFinishPlrMsgEntry(int16_t dInc);
void    MarkPlanetsPlayerLost(int16_t iPlayer);
char   *PszFormatMessage(MessageId idm, int16_t *pParams);
int16_t FSendPlrMsg2XGen(int16_t fPrepend, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2);
void    SetFilteringGroups(MessageId idm, int16_t fSet);
int16_t FSendPlrMsg2(int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2);
void    ReadPlayerMessages(void);
int16_t FSendPrependedPlrMsg(int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6, int16_t p7);
void    MarkPlayersThatSentMsgs(int16_t iPlayer);
void    ResetMessages(void);
int16_t FRemovePlayerMessage(int16_t iPlr, MessageId iMsg, int16_t iObj);
char   *PszFormatString(char *pszFormat, int16_t *pParamsReal);
char   *PszGetCompressedMessage(MessageId idm);
void    WritePlayerMessages(int16_t iPlayer);
int16_t IMsgPrev(int16_t fFilteredOnly);
int16_t IMsgNext(int16_t fFilteredOnly);
char   *PszFormatIds(StringId ids, int16_t *pParams);
int16_t FSendPlrMsg(int16_t iPlr, MessageId iMsg, int16_t iObj, int16_t p1, int16_t p2, int16_t p3, int16_t p4, int16_t p5, int16_t p6, int16_t p7);

#ifdef _WIN32

INT_PTR CALLBACK SerialDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK MessageWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

void    DecorateMsgTitleBar(HDC hdc, RECT *prc);
int16_t HtMsgBox(POINT pt);
void    SetMsgTitle(HWND hwnd);

#endif /* _WIN32 */

#endif /* MSG_H_ */
