
#include "types.h"

#include "utilgen.h"

/* globals */
char aPNCmpr[4099];  /* MEMORY_UTILGEN:0x0000 */
uint8_t acPN[999];  /* MEMORY_UTILGEN:0x1004 */
int16_t aiPNChunkOffset[16];  /* MEMORY_UTILGEN:0x13ec */
char rgPNLookupTable[52];  /* MEMORY_UTILGEN:0x140c */
int16_t rgPrimes[128];  /* MEMORY_UTILGEN:0x14ea */

/* functions */
void DrawProgressGauge(uint16_t hdcOrig, int16_t fFull, int16_t iNumOnly)
{
    uint16_t hdc;
    int16_t dy;
    int16_t fNumOnly;
    int16_t dx2;
    int16_t dx;
    RECT rc;
    int16_t c;
    char szT[8];

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x675d */
    /* label LRelease @ MEMORY_UTILGEN:0x6841 */

    /* TODO: implement */
}

int16_t AlertSz(char *sz, int16_t mbType)
{
    char szT[256];

    /* TODO: implement */
    return 0;
}

void ShowProgressGauge(void)
{

    /* TODO: implement */
}

int16_t FCheckPassword(void)
{
    int16_t (* lpProc)(void);
    int16_t fRet;
    int32_t lSaltDef;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x592a */

    /* TODO: implement */
    return 0;
}

int16_t PasswordDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    char szPass[60];
    RECT rc;
    int32_t lSalt;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x5b3d */

    /* TODO: implement */
    return 0;
}

int16_t ProgressGaugeDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    uint16_t hdc;
    PAINTSTRUCT ps;
    RECT rc;
    int16_t dy;
    char *psz;
    int16_t dx;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x648d */

    /* TODO: implement */
    return 0;
}

uint16_t HbrGet(uint32_t cr)
{
    int16_t iFree;
    int16_t i;
    uint16_t hbr;

    /* TODO: implement */
    return 0;
}

int16_t CParseNumbers(char *psz, int32_t *pl, int16_t cMax)
{
    int16_t iRead;
    int16_t fValid;
    int32_t lNum;

    /* TODO: implement */
    return 0;
}

void ExpandRc(RECT *prc, int16_t dx, int16_t dy)
{

    /* TODO: implement */
}

void CtrTextOut(uint16_t hdc, int16_t x, int16_t y, char *psz, int16_t cLen)
{
    int16_t dx;

    /* TODO: implement */
}

uint16_t HdibLoadBigResource(int16_t idb)
{
    uint16_t hrsrc;
    char * lpstr;
    int16_t hfile;
    uint16_t hdib;

    /* debug symbols */
    /* label FreeAndFail @ MEMORY_UTILGEN:0x5298 */
    /* label CloseAndFail @ MEMORY_UTILGEN:0x52c6 */

    /* TODO: implement */
    return 0;
}

void HideProgressGauge(void)
{

    /* TODO: implement */
}

void InitBtnTrack(BTNT *pbtnt, uint16_t hwnd, uint16_t hdc, RECT *prc, int16_t btf, int16_t dTimer, int16_t fInitDown, int16_t fNoEndRedraw, char *szText)
{

    /* TODO: implement */
}

int16_t FDecompressUserString(char *szIn, int16_t cIn, char *szOut, int16_t *pcOut)
{
    int16_t fHalf;
    char szWork[1024];
    int16_t iNyb;
    char *pchOut;

    /* TODO: implement */
    return 0;
}

void RcCtrTextOut(uint16_t hdc, RECT *prc, char *psz, int16_t cLen)
{
    int16_t y;
    int16_t x;
    int32_t l;

    /* TODO: implement */
}

uint16_t DibFromBitmap(uint16_t hbm, uint32_t biStyle, uint16_t biBits, uint16_t hpal)
{
    uint16_t hdc;
    uint16_t h;
    uint32_t dwLen;
    BITMAP bm;
    BITMAPINFOHEADER bi;
    uint16_t hdib;
    BITMAPINFOHEADER * lpbi;

    /* TODO: implement */
    return 0;
}

void DrawFuzzyBorder(uint16_t hdc, RECT *prc)
{
    uint32_t crBack;
    int16_t dy;
    int16_t dx;
    uint16_t hbrSav;
    uint32_t crFore;

    /* TODO: implement */
}

int16_t ReadBigBlock(int16_t hFile, char *lpBuffer, uint32_t dwSize)
{
    int16_t nBytes;
    char * lpInBuf;

    /* TODO: implement */
    return 0;
}

char * PszFromLongK(int32_t l, int16_t *pcch)
{
    int16_t fExtraLarge;
    int16_t fLarge;
    char *psz;

    /* TODO: implement */
    return NULL;
}

uint32_t GetDiskSerialNumber(void)
{
    int16_t j;
    int16_t drive;
    char fn[13];
    FIND_T fi;
    int16_t i;
    int16_t iWork;
    uint8_t uDefault;
    uint16_t uDate;
    int32_t l;
    DISKFREE_T df;

    /* debug symbols */
    /* label NoDrive @ MEMORY_UTILGEN:0x6180 */

    /* TODO: implement */
    return 0;
}

uint16_t HpalBlackReserved(void)
{
    uint16_t hpal;
    int16_t cColors;
    int16_t i;
    LOGPALETTE * ppal;

    /* TODO: implement */
    return 0;
}

int16_t FIntersectCircleLine(POINT ptL1, POINT ptL2, POINT ptC, int32_t r2, int16_t dMax, int16_t *pdStart, int16_t *pdEnd)
{
    int32_t dyT;
    int32_t dxdy;
    int16_t dCtr;
    int32_t dy2;
    int32_t dy;
    int32_t yI;
    int32_t dyI;
    int32_t dxT;
    int32_t lT;
    int32_t dx2;
    int16_t dOff;
    int32_t dx;
    int32_t dxI;
    int32_t xI;
    int32_t r2I;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x5464 */

    /* TODO: implement */
    return 0;
}

void Randomize2(uint32_t dw)
{
    int16_t a;
    int16_t b;

    /* TODO: implement */
}

void Randomize(uint32_t dw)
{
    int16_t a;
    int16_t b;

    /* TODO: implement */
}

int16_t CchGetString(int16_t ids, char *psz)
{
    char *pszT;
    char *pszTT;

    /* TODO: implement */
    return 0;
}

int32_t LSaltFromSz(char *psz)
{
    int32_t lSalt;

    /* TODO: implement */
    return 0;
}

int16_t FGetRMouseMove(POINT *ppt)
{
    MSG msg;

    /* TODO: implement */
    return 0;
}

uint16_t HfontPrinterCreate(uint16_t hdc, int16_t iSize, int16_t *pdyFont)
{
    uint16_t hfontNew;
    LOGFONT * plf;
    TEXTMETRIC tm;
    uint16_t hfontSav;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x6b28 */

    /* TODO: implement */
    return 0;
}

int16_t FStringFitsScreen(char *lpsz, int16_t dxMax)
{
    uint16_t hdc;
    int16_t c;
    int16_t fFit;
    uint16_t hfontSav;

    /* TODO: implement */
    return 0;
}

uint16_t DibNumColors(void *pv)
{
    int16_t bits;
    BITMAPCOREHEADER * lpbc;
    BITMAPINFOHEADER * lpbi;

    /* TODO: implement */
    return 0;
}

void RightTextOut(uint16_t hdc, int16_t x, int16_t y, char *psz, int16_t cLen, int16_t dxErase)
{
    int16_t dx;
    RECT rc;

    /* TODO: implement */
}

void DrawBtn(uint16_t hdc, RECT *prc, int16_t bt, int16_t fDown, char *szText)
{
    int32_t dxFace;
    int16_t ipt;
    int16_t dyOffset;
    int16_t d;
    int16_t fBar;
    int16_t fDisabled;
    int16_t dxOffset;
    int16_t dy;
    int16_t fNoShaft;
    int16_t y;
    POINT rgptDraw[6];
    uint16_t hbrCur;
    uint32_t crSav;
    int16_t dx;
    uint16_t hbrSav;
    int16_t cpt;
    int16_t x;
    RECT rc;
    int16_t dxyT;
    int16_t bkMode;
    uint16_t hfontSav;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x3d00 */
    /* block (block) @ MEMORY_UTILGEN:0x404f */
    /* label DrawAgain @ MEMORY_UTILGEN:0x3e1e */

    /* TODO: implement */
}

void _Draw3dFrame(uint16_t hdc, RECT *prc, int16_t fErase)
{
    int16_t dy;
    int16_t dx;
    uint16_t hbrSav;
    RECT rc;

    /* TODO: implement */
}

int16_t FCompressUserString(char *szIn, char *szOut, int16_t *pcOut)
{
    int16_t fHalf;
    char szWork[1024];
    int16_t iNyb;
    char *pchOut;
    int16_t cNyb;

    /* TODO: implement */
    return 0;
}

void CopyFile(char *szSrc, char *szDst)
{
    char rgb[2048];
    int16_t fFileErrSav;
    OFSTRUCT of;
    int16_t env[9];
    int16_t hfDst;
    int32_t cb;
    int16_t (* penvSav)[9];

    /* debug symbols */
    /* label LStreamError @ MEMORY_UTILGEN:0x2130 */

    /* TODO: implement */
}

int32_t LGetNextFileXor(void)
{
    int32_t s1;
    int32_t k;
    int32_t s2;

    /* TODO: implement */
    return 0;
}

void BoundPoints(RECT *prc, POINT *rgpt, int16_t cpt)
{
    int16_t ipt;
    int16_t xMax;
    int16_t yMax;
    int16_t xMin;
    int16_t yMin;

    /* TODO: implement */
}

uint16_t HpalFromDib(uint16_t hdib)
{
    uint16_t hpal;
    int16_t cColors;
    int16_t i;
    uint8_t bT;
    char * lpb;
    BITMAPINFOHEADER * lpbi;
    LOGPALETTE * ppal;

    /* TODO: implement */
    return 0;
}

int16_t DibBlt(uint16_t hdc, int16_t x0, int16_t y0, int16_t dx, int16_t dy, uint16_t hdib, int16_t x1, int16_t y1, int16_t dxSrc, int16_t dySrc, int32_t rop)
{
    char * pBuf;
    BITMAPINFOHEADER * lpbi;

    /* TODO: implement */
    return 0;
}

int16_t RandomSeedDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    char szValue[33];
    char *pch;
    uint32_t dw;
    RECT rc;

    /* TODO: implement */
    return 0;
}

void ChopTrailingSpaces(char *pBeg, char * *ppEnd)
{

    /* TODO: implement */
}

int16_t FGetMouseMove(POINT *ppt)
{
    MSG msg;

    /* TODO: implement */
    return 0;
}

void PopRandom(void)
{

    /* TODO: implement */
}

void SetFileSeeds(int32_t l1, int32_t l2)
{

    /* TODO: implement */
}

void GetFileSeeds(int32_t *pl1, int32_t *pl2)
{

    /* TODO: implement */
}

void SetFileXorStream(int32_t lid, int16_t lSalt, int16_t turn, int16_t iPlayer, int16_t fCrippled)
{
    int16_t a;
    int16_t b;

    /* TODO: implement */
}

void XorFileBuf(char *rgb, int16_t cb)
{
    int32_t * plMac;
    int32_t * pl;
    int32_t lPrev;
    char *pch;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x1d21 */

    /* TODO: implement */
}

char * PszGetLine(char * *ppszBeg)
{
    char *pszStart;
    char *psz;

    /* TODO: implement */
    return NULL;
}

int16_t Random(int16_t c)
{
    int32_t z;
    int32_t s1;
    int32_t k;
    int32_t s2;

    /* TODO: implement */
    return 0;
}

char * PszFromLong(int32_t l, int16_t *pcch)
{
    int16_t cch;

    /* TODO: implement */
    return NULL;
}

void PushRandom(int32_t lNew1, int32_t lNew2)
{

    /* TODO: implement */
}

void OffsetRc(RECT *prc, int16_t dx, int16_t dy)
{

    /* TODO: implement */
}

void StickyDlgPos(uint16_t hwnd, POINT *ppt, int16_t fInit)
{
    POINT ptScreenMax;
    RECT rc;

    /* TODO: implement */
}

void UpdateProgressGauge(int16_t pctX10)
{
    int16_t iNum;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x63ed */

    /* TODO: implement */
}

int16_t ICompLong(void *arg1, void *arg2)
{

    /* TODO: implement */
    return 0;
}

char * PszFromInt(int16_t i, int16_t *pcch)
{
    int16_t cch;

    /* TODO: implement */
    return NULL;
}

void AddBackTrailingSpaces(char * *ppch, char *pchEnd)
{

    /* TODO: implement */
}

uint16_t PaletteSize(void *pv)
{
    uint16_t NumColors;
    BITMAPINFOHEADER * lpbi;

    /* TODO: implement */
    return 0;
}

int32_t LDistance2(POINT pt1, POINT pt2)
{
    int32_t dy;
    int32_t dx;

    /* TODO: implement */
    return 0;
}

void ChopLastWord(char *pBeg, char * *ppEnd)
{

    /* TODO: implement */
}

void FreeHbr(uint16_t hbr)
{
    int16_t i;

    /* debug symbols */
    /* label DeleteBrush @ MEMORY_UTILGEN:0x457d */

    /* TODO: implement */
}

int16_t FTrackBtn(BTNT *pbtnt)
{
    POINT pt;
    int16_t fInBtn;
    int32_t ticksNew;

    /* TODO: implement */
    return 0;
}

int16_t NybbleFromCh(uint8_t ch)
{
    char *pch;

    /* TODO: implement */
    return 0;
}

void IntToRoman(int16_t i, char *pszOut)
{

    /* TODO: implement */
}

int16_t NewPasswordDlg(uint16_t hwnd, uint16_t message, uint16_t wParam, int32_t lParam)
{
    char szPass[20];
    RECT rc;
    int32_t lSalt2;
    int32_t lSalt;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x5de8 */

    /* TODO: implement */
    return 0;
}

void WrapTextOut(uint16_t hdc, int16_t *px, int16_t *py, char *psz, int16_t cLen, int16_t xLeft, int16_t dxWidth, int16_t *pxMax, int16_t fNewLine, int16_t fPrint)
{
    int16_t dxRemain;
    char *pchEnd;
    int16_t fItFit;
    int16_t xRight;
    int16_t dx;
    char *pchStart;
    char *pch;

    /* debug symbols */
    /* label WrapIt @ MEMORY_UTILGEN:0x27c5 */
    /* label Done @ MEMORY_UTILGEN:0x2802 */
    /* label Top @ MEMORY_UTILGEN:0x2656 */

    /* TODO: implement */
}

int16_t DxStreamTextOut(uint16_t hdc, int16_t *px, int16_t y, char *psz, int16_t cLen, int16_t fPrint)
{
    int16_t dx;

    /* TODO: implement */
    return 0;
}

void OutputFileString(char *szFile, char *sz)
{
    OFSTRUCT of;
    uint16_t w;
    int16_t hf;

    /* TODO: implement */
}

char * PszGetCompressedPlanet(int16_t id)
{
    int16_t fCap;
    int16_t iOffset;
    int16_t fHigh;
    int16_t iChunk;
    int16_t i;
    int16_t iBuild;
    int16_t iNibble;
    char *pchLen;
    char *pszOut;
    char *pch;
    int16_t iLen;

    /* TODO: implement */
    return NULL;
}

int32_t LDrawGauge(uint16_t hdc, RECT *prc, int16_t cSegs, int32_t *rgSize, uint16_t *rghbr, int32_t cTot)
{
    int16_t fHuge;
    int16_t i;
    int32_t lSum;
    int32_t dx;
    RECT rc;

    /* debug symbols */
    /* label FinRet @ MEMORY_UTILGEN:0x330e */

    /* TODO: implement */
    return 0;
}

int16_t CommaFormatLong(char *psz, int32_t l)
{
    char rgch[15];
    int16_t c;
    int16_t cSkip;
    char *pchOut;
    char *pch;

    /* TODO: implement */
    return 0;
}

char ChFromNybble(int16_t nyb)
{
    int16_t iPage;
    int16_t iVal;

    /* TODO: implement */
    return 0;
}

void DiaganolTextOut(uint16_t hdc, RECT *prc, char *psz, int16_t cLen)
{
    double angle;
    uint16_t hfont;
    int16_t dxFlat;
    int16_t yStart;
    int16_t dy;
    double dcos;
    int16_t dyText;
    int16_t xStart;
    int16_t dyEstFont;
    int16_t dxText;
    LOGFONT * plf;
    double dsin;
    uint16_t hfontSav;
    int16_t dx;
    int16_t dyFlat;
    double rotate;
    int32_t l;
    int16_t dHtX;
    int16_t dHtY;

    /* debug symbols */
    /* block (block) @ MEMORY_UTILGEN:0x2d9a */
    /* label TryAgain @ MEMORY_UTILGEN:0x2b97 */
    /* label FreeLF @ MEMORY_UTILGEN:0x2efd */

    /* TODO: implement */
}
