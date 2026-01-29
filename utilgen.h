#ifndef UTILGEN_H_
#define UTILGEN_H_

#include "types.h"
#include "strings.h"

/* globals */
extern char aPNCmpr[4099];          /* MEMORY_UTILGEN:0x0000 */
extern uint8_t acPN[999];           /* MEMORY_UTILGEN:0x1004 */
extern int16_t aiPNChunkOffset[16]; /* MEMORY_UTILGEN:0x13ec */
extern char rgPNLookupTable[52];    /* MEMORY_UTILGEN:0x140c */
extern int16_t rgPrimes[128];       /* MEMORY_UTILGEN:0x14ea */

extern char rgchcomp[13];
extern int16_t rgcompstrlower[26];
extern char *rgchcompstrlower;

/* functions */
int16_t NybbleFromCh(uint8_t ch);                                                                                            /* MEMORY_UTILGEN:0x4880 */
char ChFromNybble(int16_t nyb);                                                                                              /* MEMORY_UTILGEN:0x49ea */
int16_t FDecompressUserString(char *szIn, int16_t cIn, char *szOut, int16_t *pcOut);                                         /* MEMORY_UTILGEN:0x46e8 */
int16_t FCompressUserString(char *szIn, char *szOut, int16_t *pcOut);                                                        /* MEMORY_UTILGEN:0x45a0 */
void ShowProgressGauge(void);                                                                                                /* MEMORY_UTILGEN:0x636c */
int16_t FCheckPassword(void);                                                                                                /* MEMORY_UTILGEN:0x58d8 */
int16_t CParseNumbers(char *psz, int32_t *pl, int16_t cMax);                                                                 /* MEMORY_UTILGEN:0x6986 */
void ExpandRc(RECT *prc, int16_t dx, int16_t dy);                                                                            /* MEMORY_UTILGEN:0x2f0c */
int16_t ReadBigBlock(int16_t hFile, char *lpBuffer, uint32_t dwSize);                                                        /* MEMORY_UTILGEN:0x5310 */
char *PszFromLongK(int32_t l, int16_t *pcch);                                                                                /* MEMORY_UTILGEN:0x22fe */
uint32_t GetDiskSerialNumber(void);                                                                                          /* MEMORY_UTILGEN:0x5fc0 */
int16_t FIntersectCircleLine(POINT ptL1, POINT ptL2, POINT ptC, int32_t r2, int16_t dMax, int16_t *pdStart, int16_t *pdEnd); /* MEMORY_UTILGEN:0x53b4 */
void Randomize2(uint32_t dw);                                                                                                /* MEMORY_UTILGEN:0x165a */
void Randomize(uint32_t dw);                                                                                                 /* MEMORY_UTILGEN:0x15ea */
int16_t CchGetString(StringId ids, char *psz);                                                                               /* MEMORY_UTILGEN:0x221e */
int32_t LSaltFromSz(char *psz);                                                                                              /* MEMORY_UTILGEN:0x59ce */
void CopyStarsFile(char *szSrc, char *szDst);                                                                                /* MEMORY_UTILGEN:0x1ffa */
uint32_t LGetNextFileXor(void);                                                                                              /* MEMORY_UTILGEN:0x1b54 */
void BoundPoints(RECT *prc, POINT *rgpt, int16_t cpt);                                                                       /* MEMORY_UTILGEN:0x2f70 */
void ChopTrailingSpaces(char *pBeg, char **ppEnd);                                                                           /* MEMORY_UTILGEN:0x28c6 */
void PopRandom(void);                                                                                                        /* MEMORY_UTILGEN:0x14a2 */
void SetFileSeeds(int32_t l1, int32_t l2);                                                                                   /* MEMORY_UTILGEN:0x1a7c */
void GetFileSeeds(int32_t *pl1, int32_t *pl2);                                                                               /* MEMORY_UTILGEN:0x1a4e */
void SetFileXorStream(int32_t lid, int16_t lSalt, int16_t turn, int16_t iPlayer, int16_t fCrippled);                         /* MEMORY_UTILGEN:0x1aa6 */
void XorFileBuf(uint8_t *rgb, int16_t cb);                                                                                   /* MEMORY_UTILGEN:0x1cc4 */
char *PszGetLine(char **ppszBeg); /* RETFAR */                                                                               /* MEMORY_UTILGEN:0x68ba */
int16_t Random(int16_t c);                                                                                                   /* MEMORY_UTILGEN:0x16d2 */
char *PszFromLong(int32_t l, int16_t *pcch);                                                                                 /* MEMORY_UTILGEN:0x22b6 */
void PushRandom(int32_t lNew1, int32_t lNew2);                                                                               /* MEMORY_UTILGEN:0x1440 */
void OffsetRc(RECT *prc, int16_t dx, int16_t dy);                                                                            /* MEMORY_UTILGEN:0x2f3e */
int16_t ICompLong(void *arg1, void *arg2);                                                                                   /* MEMORY_UTILGEN:0x1d74 */
char *PszFromInt(int16_t i, int16_t *pcch);                                                                                  /* MEMORY_UTILGEN:0x2274 */
void AddBackTrailingSpaces(char **ppch, char *pchEnd);                                                                       /* MEMORY_UTILGEN:0x280c */
int32_t LDistance2(POINT pt1, POINT pt2);                                                                                    /* MEMORY_UTILGEN:0x685c */
void ChopLastWord(char *pBeg, char **ppEnd);                                                                                 /* MEMORY_UTILGEN:0x2842 */
void IntToRoman(int16_t i, char *pszOut);                                                                                    /* MEMORY_UTILGEN:0x5830 */
void OutputFileString(char *szFile, char *sz);                                                                               /* MEMORY_UTILGEN:0x1f64 */
char *PszGetCompressedPlanet(int16_t id);                                                                                    /* MEMORY_UTILGEN:0x1d96 */
int16_t CommaFormatLong(char *psz, int32_t l);                                                                               /* MEMORY_UTILGEN:0x2440 */

#ifdef _WIN32

INT_PTR CALLBACK RandomSeedDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);    /* MEMORY_UTILGEN:0x188a */
INT_PTR CALLBACK PasswordDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);      /* MEMORY_UTILGEN:0x5a72 */
INT_PTR CALLBACK ProgressGaugeDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); /* MEMORY_UTILGEN:0x647e */
INT_PTR CALLBACK NewPasswordDlg(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);   /* MEMORY_UTILGEN:0x5cba */

int AlertSz(const char *sz, UINT mbType);
HGLOBAL HdibLoadBigResource(int idb);
HBRUSH HbrGet(COLORREF cr);                                                                                                                        /* MEMORY_UTILGEN:0x4448 */
void CtrTextOut(HDC hdc, int16_t x, int16_t y, char *psz, int16_t cLen);                                                                           /* MEMORY_UTILGEN:0x2534 */
void HideProgressGauge(void);                                                                                                                      /* MEMORY_UTILGEN:0x63b2 */
void InitBtnTrack(BTNT *pbtnt, HWND hwnd, HDC hdc, RECT *prc, int16_t btf, int16_t dTimer, int16_t fInitDown, int16_t fNoEndRedraw, char *szText); /* MEMORY_UTILGEN:0x354c */
void RcCtrTextOut(HDC hdc, RECT *prc, char *psz, int16_t cLen);                                                                                    /* MEMORY_UTILGEN:0x28fc */
HGLOBAL DibFromBitmap(HBITMAP hbm, DWORD biCompression, WORD biBits, HPALETTE hpal);
void DrawFuzzyBorder(HDC hdc, RECT *prc);                           /* MEMORY_UTILGEN:0x427a */
HPALETTE HpalBlackReserved(void);                                   /* MEMORY_UTILGEN:0x4c9c */
int16_t FGetRMouseMove(POINT *ppt);                                 /* MEMORY_UTILGEN:0x41e0 */
HFONT HfontPrinterCreate(HDC hdc, int16_t iSize, int16_t *pdyFont); /* MEMORY_UTILGEN:0x6aa6 */
int16_t FStringFitsScreen(char *lpsz, int16_t dxMax);               /* MEMORY_UTILGEN:0x43aa */
uint32_t DibNumColors(const void *pv);
void RightTextOut(HDC hdc, int16_t x, int16_t y, char *psz, int16_t cLen, int16_t dxErase); /* MEMORY_UTILGEN:0x29d6 */
void DrawBtn(HDC hdc, RECT *prc, int16_t bt, int16_t fDown, char *szText);                  /* MEMORY_UTILGEN:0x38b8 */
void _Draw3dFrame(HDC hdc, RECT *prc, int16_t fErase);                                      /* MEMORY_UTILGEN:0x336a */
HPALETTE HpalFromDib(HGLOBAL hdib);                                                         /* MEMORY_UTILGEN:0x4b50 */
int16_t DibBlt(HDC hdc,
               int32_t x0, int32_t y0, int32_t dx, int32_t dy,
               HGLOBAL hdib,
               int32_t x1, int32_t y1, int32_t dxSrc, int32_t dySrc,
               int32_t rop);
int16_t FGetMouseMove(POINT *ppt);                       /* MEMORY_UTILGEN:0x4146 */
void StickyDlgPos(HWND hwnd, POINT *ppt, int16_t fInit); /* MEMORY_UTILGEN:0x3094 */
void UpdateProgressGauge(int16_t pctX10);                /* MEMORY_UTILGEN:0x63da */
uint32_t PaletteSize(const void *pv);
void FreeHbr(HBRUSH hbr);                                                                                                                                       /* MEMORY_UTILGEN:0x4532 */
int16_t FTrackBtn(BTNT *pbtnt);                                                                                                                                 /* MEMORY_UTILGEN:0x364a */
void WrapTextOut(HDC hdc, int16_t *px, int16_t *py, char *psz, int16_t cLen, int16_t xLeft, int16_t dxWidth, int16_t *pxMax, int16_t fNewLine, int16_t fPrint); /* MEMORY_UTILGEN:0x25fe */
int16_t DxStreamTextOut(HDC hdc, int16_t *px, int16_t y, char *psz, int16_t cLen, int16_t fPrint);                                                              /* MEMORY_UTILGEN:0x2590 */
int32_t LDrawGauge(HDC hdc, RECT *prc, int16_t cSegs, int32_t *rgSize, HBRUSH *rghbr, int32_t cTot);                                                            /* MEMORY_UTILGEN:0x31a2 */
void DiaganolTextOut(HDC hdc, RECT *prc, char *psz, int16_t cLen);                                                                                              /* MEMORY_UTILGEN:0x2afa */
void DrawProgressGauge(HDC hdcOrig, int16_t fFull, int16_t iNumOnly);                                                                                           /* MEMORY_UTILGEN:0x65f6 */

#else
// special case because this is called everywhere, do nothing outside of win32
// TODO: make this multiplatform since it's called all over
int16_t AlertSz(const char *sz, uint16_t mbType);
#endif /* _WIN32 */
#endif /* UTILGEN_H_ */
