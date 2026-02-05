#ifndef UTILGEN_H_
#define UTILGEN_H_

#include "strings.h"
#include "types.h"

/* globals */
extern char    aPNCmpr[4099];
extern uint8_t acPN[999];
extern int16_t aiPNChunkOffset[16];
extern char    rgPNLookupTable[52];
extern int16_t rgPrimes[128];

extern char    rgchcomp[13];
extern int16_t rgcompstrlower[26];
extern char   *rgchcompstrlower;

/* functions */
int16_t  NybbleFromCh(uint8_t ch);
char     ChFromNybble(int16_t nyb);
int16_t  FDecompressUserString(char *szIn, int16_t cIn, char *szOut, int16_t *pcOut);
int16_t  FCompressUserString(char *szIn, char *szOut, int16_t *pcOut);
void     ShowProgressGauge(void);
int16_t  FCheckPassword(void);
int16_t  CParseNumbers(char *psz, int32_t *pl, int16_t cMax);
void     ExpandRc(RECT *prc, int16_t dx, int16_t dy);
int16_t  ReadBigBlock(int16_t hFile, char *lpBuffer, uint32_t dwSize);
char    *PszFromLongK(int32_t l, int16_t *pcch);
uint32_t GetDiskSerialNumber(void);
int16_t  FIntersectCircleLine(POINT ptL1, POINT ptL2, POINT ptC, int32_t r2, int16_t dMax, int16_t *pdStart, int16_t *pdEnd);
void     Randomize2(uint32_t dw);
void     Randomize(uint32_t dw);
int16_t  CchGetString(StringId ids, char *psz);
int32_t  LSaltFromSz(char *psz);
void     CopyStarsFile(char *szSrc, char *szDst);
uint32_t LGetNextFileXor(void);
void     BoundPoints(RECT *prc, POINT *rgpt, int16_t cpt);
void     ChopTrailingSpaces(char *pBeg, char **ppEnd);
void     PopRandom(void);
void     SetFileSeeds(int32_t l1, int32_t l2);
void     GetFileSeeds(int32_t *pl1, int32_t *pl2);
void     SetFileXorStream(int32_t lid, int16_t lSalt, int16_t turn, int16_t iPlayer, int16_t fCrippled);
void     XorFileBuf(uint8_t *rgb, int16_t cb);
char    *PszGetLine(char **ppszBeg); /* RETFAR */
int16_t  Random(int16_t c);
char    *PszFromLong(int32_t l, int16_t *pcch);
void     PushRandom(int32_t lNew1, int32_t lNew2);
void     OffsetRc(RECT *prc, int16_t dx, int16_t dy);
int      ICompLong(const void *arg1, const void *arg2);
char    *PszFromInt(int16_t i, int16_t *pcch);
void     AddBackTrailingSpaces(char **ppch, char *pchEnd);
int32_t  LDistance2(POINT pt1, POINT pt2);
void     ChopLastWord(char *pBeg, char **ppEnd);
void     IntToRoman(int16_t i, char *pszOut);
void     OutputFileString(char *szFile, char *sz);
char    *PszGetCompressedPlanet(int16_t id);
int16_t  CommaFormatLong(char *psz, int32_t l);
void     UpdateProgressGauge(int16_t pctX10);

#ifdef _WIN32

INT_PTR CALLBACK RandomSeedDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PasswordDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK ProgressGaugeDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK NewPasswordDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

int      AlertSz(const char *sz, UINT mbType);
HGLOBAL  HdibLoadBigResource(int idb);
HBRUSH   HbrGet(COLORREF cr);
void     CtrTextOut(HDC hdc, int16_t x, int16_t y, char *psz, int16_t cLen);
void     HideProgressGauge(void);
void     InitBtnTrack(BTNT *pbtnt, HWND hwnd, HDC hdc, RECT *prc, int16_t btf, int16_t dTimer, int16_t fInitDown, int16_t fNoEndRedraw, char *szText);
void     RcCtrTextOut(HDC hdc, RECT *prc, char *psz, int16_t cLen);
HGLOBAL  DibFromBitmap(HBITMAP hbm, DWORD biCompression, WORD biBits, HPALETTE hpal);
void     DrawFuzzyBorder(HDC hdc, RECT *prc);
HPALETTE HpalBlackReserved(void);
int16_t  FGetRMouseMove(POINT *ppt);
HFONT    HfontPrinterCreate(HDC hdc, int16_t iSize, int16_t *pdyFont);
int16_t  FStringFitsScreen(char *lpsz, int16_t dxMax);
uint32_t DibNumColors(const void *pv);
void     RightTextOut(HDC hdc, int16_t x, int16_t y, char *psz, int16_t cLen, int16_t dxErase);
void     DrawBtn(HDC hdc, RECT *prc, int16_t bt, int16_t fDown, char *szText);
void     _Draw3dFrame(HDC hdc, RECT *prc, int16_t fErase);
HPALETTE HpalFromDib(HGLOBAL hdib);
int16_t  DibBlt(HDC hdc, int32_t x0, int32_t y0, int32_t dx, int32_t dy, HGLOBAL hdib, int32_t x1, int32_t y1, int32_t dxSrc, int32_t dySrc, int32_t rop);
int16_t  FGetMouseMove(POINT *ppt);
void     StickyDlgPos(HWND hwnd, POINT *ppt, int16_t fInit);
uint32_t PaletteSize(const void *pv);
void     FreeHbr(HBRUSH hbr);
int16_t  FTrackBtn(BTNT *pbtnt);
void WrapTextOut(HDC hdc, int16_t *px, int16_t *py, char *psz, int16_t cLen, int16_t xLeft, int16_t dxWidth, int16_t *pxMax, int16_t fNewLine, int16_t fPrint);
int16_t DxStreamTextOut(HDC hdc, int16_t *px, int16_t y, char *psz, int16_t cLen, int16_t fPrint);
int32_t LDrawGauge(HDC hdc, RECT *prc, int16_t cSegs, int32_t *rgSize, HBRUSH *rghbr, int32_t cTot);
void    DiaganolTextOut(HDC hdc, RECT *prc, char *psz, int16_t cLen);
void    DrawProgressGauge(HDC hdcOrig, int16_t fFull, int16_t iNumOnly);

#else
// special case because this is called everywhere, do nothing outside of win32
// TODO: make this multiplatform since it's called all over
int16_t AlertSz(const char *sz, uint16_t mbType);
#endif /* _WIN32 */
#endif /* UTILGEN_H_ */
