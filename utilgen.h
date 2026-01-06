#ifndef UTILGEN_H_
#define UTILGEN_H_


#include "types.h"

/* globals */
extern char aPNCmpr[4099];  /* MEMORY_UTILGEN:0x0000 */
extern uint8_t acPN[999];  /* MEMORY_UTILGEN:0x1004 */
extern int16_t aiPNChunkOffset[16];  /* MEMORY_UTILGEN:0x13ec */
extern char rgPNLookupTable[52];  /* MEMORY_UTILGEN:0x140c */
extern int16_t rgPrimes[128];  /* MEMORY_UTILGEN:0x14ea */

/* functions */
void DrawProgressGauge(uint16_t, int16_t, int16_t);  /* MEMORY_UTILGEN:0x65f6 */
int16_t AlertSz(char *, int16_t);  /* MEMORY_UTILGEN:0x2160 */
void ShowProgressGauge(void);  /* MEMORY_UTILGEN:0x636c */
int16_t FCheckPassword(void);  /* MEMORY_UTILGEN:0x58d8 */
int16_t PasswordDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_UTILGEN:0x5a72 */
int16_t ProgressGaugeDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_UTILGEN:0x647e */
uint16_t HbrGet(uint32_t);  /* MEMORY_UTILGEN:0x4448 */
int16_t CParseNumbers(char *, int32_t *, int16_t);  /* MEMORY_UTILGEN:0x6986 */
void ExpandRc(RECT *, int16_t, int16_t);  /* MEMORY_UTILGEN:0x2f0c */
void CtrTextOut(uint16_t, int16_t, int16_t, char *, int16_t);  /* MEMORY_UTILGEN:0x2534 */
uint16_t HdibLoadBigResource(int16_t);  /* MEMORY_UTILGEN:0x5220 */
void HideProgressGauge(void);  /* MEMORY_UTILGEN:0x63b2 */
void InitBtnTrack(BTNT *, uint16_t, uint16_t, RECT *, int16_t, int16_t, int16_t, int16_t, char *);  /* MEMORY_UTILGEN:0x354c */
int16_t FDecompressUserString(char *, int16_t, char *, int16_t *);  /* MEMORY_UTILGEN:0x46e8 */
void RcCtrTextOut(uint16_t, RECT *, char *, int16_t);  /* MEMORY_UTILGEN:0x28fc */
uint16_t DibFromBitmap(uint16_t, uint32_t, uint16_t, uint16_t);  /* MEMORY_UTILGEN:0x4e90 */
void DrawFuzzyBorder(uint16_t, RECT *);  /* MEMORY_UTILGEN:0x427a */
int16_t ReadBigBlock(int16_t, char *, uint32_t);  /* MEMORY_UTILGEN:0x5310 */
char * PszFromLongK(int32_t, int16_t *);  /* MEMORY_UTILGEN:0x22fe */
uint32_t GetDiskSerialNumber(void);  /* MEMORY_UTILGEN:0x5fc0 */
uint16_t HpalBlackReserved(void);  /* MEMORY_UTILGEN:0x4c9c */
int16_t FIntersectCircleLine(POINT, POINT, POINT, int32_t, int16_t, int16_t *, int16_t *);  /* MEMORY_UTILGEN:0x53b4 */
void Randomize2(uint32_t);  /* MEMORY_UTILGEN:0x165a */
void Randomize(uint32_t);  /* MEMORY_UTILGEN:0x15ea */
int16_t CchGetString(int16_t, char *);  /* MEMORY_UTILGEN:0x221e */
int32_t LSaltFromSz(char *);  /* MEMORY_UTILGEN:0x59ce */
int16_t FGetRMouseMove(POINT *);  /* MEMORY_UTILGEN:0x41e0 */
uint16_t HfontPrinterCreate(uint16_t, int16_t, int16_t *);  /* MEMORY_UTILGEN:0x6aa6 */
int16_t FStringFitsScreen(char *, int16_t);  /* MEMORY_UTILGEN:0x43aa */
uint16_t DibNumColors(void *);  /* MEMORY_UTILGEN:0x4a9a */
void RightTextOut(uint16_t, int16_t, int16_t, char *, int16_t, int16_t);  /* MEMORY_UTILGEN:0x29d6 */
void DrawBtn(uint16_t, RECT *, int16_t, int16_t, char *);  /* MEMORY_UTILGEN:0x38b8 */
void _Draw3dFrame(uint16_t, RECT *, int16_t);  /* MEMORY_UTILGEN:0x336a */
int16_t FCompressUserString(char *, char *, int16_t *);  /* MEMORY_UTILGEN:0x45a0 */
void CopyFile(char *, char *);  /* MEMORY_UTILGEN:0x1ffa */
int32_t LGetNextFileXor(void);  /* MEMORY_UTILGEN:0x1b54 */
void BoundPoints(RECT *, POINT *, int16_t);  /* MEMORY_UTILGEN:0x2f70 */
uint16_t HpalFromDib(uint16_t);  /* MEMORY_UTILGEN:0x4b50 */
int16_t DibBlt(uint16_t, int16_t, int16_t, int16_t, int16_t, uint16_t, int16_t, int16_t, int16_t, int16_t, int32_t);  /* MEMORY_UTILGEN:0x4db8 */
int16_t RandomSeedDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_UTILGEN:0x188a */
void ChopTrailingSpaces(char *, char * *);  /* MEMORY_UTILGEN:0x28c6 */
int16_t FGetMouseMove(POINT *);  /* MEMORY_UTILGEN:0x4146 */
void PopRandom(void);  /* MEMORY_UTILGEN:0x14a2 */
void SetFileSeeds(int32_t, int32_t);  /* MEMORY_UTILGEN:0x1a7c */
void GetFileSeeds(int32_t *, int32_t *);  /* MEMORY_UTILGEN:0x1a4e */
void SetFileXorStream(int32_t, int16_t, int16_t, int16_t, int16_t);  /* MEMORY_UTILGEN:0x1aa6 */
void XorFileBuf(char *, int16_t);  /* MEMORY_UTILGEN:0x1cc4 */
char * PszGetLine(char * *);  /* RETFAR */  /* MEMORY_UTILGEN:0x68ba */
int16_t Random(int16_t);  /* MEMORY_UTILGEN:0x16d2 */
char * PszFromLong(int32_t, int16_t *);  /* MEMORY_UTILGEN:0x22b6 */
void PushRandom(int32_t, int32_t);  /* MEMORY_UTILGEN:0x1440 */
void OffsetRc(RECT *, int16_t, int16_t);  /* MEMORY_UTILGEN:0x2f3e */
void StickyDlgPos(uint16_t, POINT *, int16_t);  /* MEMORY_UTILGEN:0x3094 */
void UpdateProgressGauge(int16_t);  /* MEMORY_UTILGEN:0x63da */
int16_t ICompLong(void *, void *);  /* MEMORY_UTILGEN:0x1d74 */
char * PszFromInt(int16_t, int16_t *);  /* MEMORY_UTILGEN:0x2274 */
void AddBackTrailingSpaces(char * *, char *);  /* MEMORY_UTILGEN:0x280c */
uint16_t PaletteSize(void *);  /* MEMORY_UTILGEN:0x4d60 */
int32_t LDistance2(POINT, POINT);  /* MEMORY_UTILGEN:0x685c */
void ChopLastWord(char *, char * *);  /* MEMORY_UTILGEN:0x2842 */
void FreeHbr(uint16_t);  /* MEMORY_UTILGEN:0x4532 */
int16_t FTrackBtn(BTNT *);  /* MEMORY_UTILGEN:0x364a */
int16_t NybbleFromCh(uint8_t);  /* MEMORY_UTILGEN:0x4880 */
void IntToRoman(int16_t, char *);  /* MEMORY_UTILGEN:0x5830 */
int16_t NewPasswordDlg(uint16_t, uint16_t, uint16_t, int32_t);  /* PASCAL */  /* MEMORY_UTILGEN:0x5cba */
void WrapTextOut(uint16_t, int16_t *, int16_t *, char *, int16_t, int16_t, int16_t, int16_t *, int16_t, int16_t);  /* MEMORY_UTILGEN:0x25fe */
int16_t DxStreamTextOut(uint16_t, int16_t *, int16_t, char *, int16_t, int16_t);  /* MEMORY_UTILGEN:0x2590 */
void OutputFileString(char *, char *);  /* MEMORY_UTILGEN:0x1f64 */
char * PszGetCompressedPlanet(int16_t);  /* MEMORY_UTILGEN:0x1d96 */
int32_t LDrawGauge(uint16_t, RECT *, int16_t, int32_t *, uint16_t *, int32_t);  /* MEMORY_UTILGEN:0x31a2 */
int16_t CommaFormatLong(char *, int32_t);  /* MEMORY_UTILGEN:0x2440 */
char ChFromNybble(int16_t);  /* MEMORY_UTILGEN:0x49ea */
void DiaganolTextOut(uint16_t, RECT *, char *, int16_t);  /* MEMORY_UTILGEN:0x2afa */

#endif /* UTILGEN_H_ */
