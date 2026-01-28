# Implementation Plan

Auto-generated cross-reference of call graph depth and implementation status.

*AI functions excluded (103 functions from ai.c, ai2.c, ai3.c, ai4.c, aiu.c, aiutil.c)*

## Summary

| Depth | Label | Total | Implemented | Unimplemented |
|-------|-------|------:|------------:|--------------:|
| 0 | Depth 0 — Leaf Functions | 192 | 52 | 140 |
| 1 | Depth 1 — Calls Only Leaves | 73 | 19 | 54 |
| 2 | Depth 2 | 76 | 10 | 66 |
| 3 | Depth 3 | 59 | 6 | 53 |
| 4 | Depth 4 | 46 | 4 | 42 |
| 5 | Depth 5 | 19 | 1 | 18 |
| 6 | Depth 6 | 10 | 1 | 9 |
| 7 | Depth 7 | 15 | 3 | 12 |
| 8 | Depth 8 | 15 | 3 | 12 |
| 9 | Depth 9 | 26 | 3 | 23 |
| 10 | Depth 10 | 14 | 4 | 10 |
| 11 | Depth 11 | 14 | 2 | 12 |
| 12 | Depth 12 | 20 | 0 | 20 |
| 13 | Depth 13 | 14 | 1 | 13 |
| 14 | Depth 14 | 13 | 0 | 13 |
| 15 | Depth 15 | 9 | 0 | 9 |
| 16 | Depth 16 | 8 | 2 | 6 |
| 17 | Depth 17 | 11 | 0 | 11 |
| 18 | Depth 18 | 2 | 0 | 2 |
| -1 | Depth -1 — Cyclic Functions | 107 | 2 | 105 |
| | **Total** | **743** | **113** | **630** |

## Depth 0 — Leaf Functions

### Unimplemented (140)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **DrawHostOptions** | 15 | `void DrawHostOptions(uint16_t, uint16_t, int16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **InitNewGame3** | 15 | `void InitNewGame3(void)` |  | [create.c](../decompiled/all/create.c) |
| ⬜ | **LpplrComp** | 15 | `PLAYER *32 LpplrComp(int16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **CancelMemRt** | 17 | `void CancelMemRt(int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **AddBackTrailingSpaces** | 18 | `void AddBackTrailingSpaces(char * *, char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **ChopTrailingSpaces** | 18 | `void ChopTrailingSpaces(char *, char * *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **ExpandRc** | 19 | `void ExpandRc(RECT *, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **HideProgressGauge** | 19 | `void HideProgressGauge(void)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **OffsetRc** | 19 | `void OffsetRc(RECT *, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FreeLpth** | 21 | `void FreeLpth(THING *32)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **GetTrueHullCost** | 21 | `void GetTrueHullCost(int16_t, HUL *32, uint16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **LDistance2** | 22 | `int32_t LDistance2(POINT, POINT)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **PszFromInt** | 22 | `char * PszFromInt(int16_t, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **PszFromLong** | 22 | `char * PszFromLong(int32_t, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **SetRaceStat** | 22 | `int16_t SetRaceStat(PLAYER *, int16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **CtrTextOut** | 23 | `void CtrTextOut(uint16_t, int16_t, int16_t, char *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **HandleFocusState** | 23 | `void HandleFocusState(DRAWITEMSTRUCT *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ChopLastWord** | 24 | `void ChopLastWord(char *, char * *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **EnableZipBtns** | 24 | `void EnableZipBtns(uint16_t, int16_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FFuelTanker** | 24 | `int16_t FFuelTanker(SHDEF *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **IRaceChecksum** | 24 | `uint16_t IRaceChecksum(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **SetVCCheck** | 24 | `void SetVCCheck(GAME *, int16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **DzFromBrcBrc** | 25 | `int16_t DzFromBrcBrc(uint8_t, uint8_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **IEmptyBmpFromGrhst** | 25 | `int16_t IEmptyBmpFromGrhst(int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DrawPlanetPrintDot** | 26 | `void DrawPlanetPrintDot(uint16_t, int16_t, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DxStreamTextOut** | 26 | `int16_t DxStreamTextOut(uint16_t, int16_t *, int16_t, char *, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FCanSplit** | 26 | `int16_t FCanSplit(int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FCheckResearch** | 26 | `int16_t FCheckResearch(int16_t, int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FakeEditProc** | 26 | `int32_t FakeEditProc(uint16_t, uint16_t, uint16_t, int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **GetWindowRc** | 26 | `void GetWindowRc(uint16_t, RECT *)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **IflFromLpfl** | 27 | `int16_t IflFromLpfl(FLEET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **LongFromSerialCh** | 27 | `int32_t LongFromSerialCh(char)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **PctWormholeMoves** | 27 | `int16_t PctWormholeMoves(THING *32)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **ShowTutor** | 27 | `void ShowTutor(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **UnmarkMineFields** | 27 | `void UnmarkMineFields(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FHandleChar** | 28 | `int16_t FHandleChar(uint16_t, uint16_t, int32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **ClearFile** | 29 | `void ClearFile(int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DxyFromSpdRound** | 29 | `int16_t DxyFromSpdRound(uint16_t, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **EnableZipProdBtns** | 29 | `void EnableZipProdBtns(uint16_t, int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FFindPlayerMessage** | 30 | `int16_t FFindPlayerMessage(int16_t, int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FCheckBtlPlan** | 31 | `int16_t FCheckBtlPlan(int16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FHullHasTeeth** | 31 | `int16_t FHullHasTeeth(HUL *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FColonizer** | 32 | `int16_t FColonizer(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FScout** | 32 | `int16_t FScout(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **ICompFleetPoint2** | 32 | `int16_t ICompFleetPoint2(void *, void *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DpOfLpflIshdef** | 33 | `int32_t DpOfLpflIshdef(FLEET *32, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **EnableVCRButtons** | 33 | `void EnableVCRButtons(void)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **EnumLogRts** | 33 | `void EnumLogRts(int16_t (*32)(void *32, int16_t, int16_t, void *32, int16_t), void *32, int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FCanSplitAll** | 33 | `int16_t FCanSplitAll(int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FGetPrevLogRt** | 33 | `int16_t FGetPrevLogRt(HDR *, uint8_t *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FRemovePlayerMessage** | 33 | `int16_t FRemovePlayerMessage(int16_t, int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FreeHbr** | 33 | `void FreeHbr(uint16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **HpalBlackReserved** | 33 | `uint16_t HpalBlackReserved(void)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FStringFitsScreen** | 34 | `int16_t FStringFitsScreen(char *32, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **InitBtnTrack** | 34 | `void InitBtnTrack(BTNT *, uint16_t, uint16_t, RECT *, int16_t, int16_t, int16_t, int16_t, char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **IStargateFromLppl** | 35 | `int16_t IStargateFromLppl(PLANET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **CreateShip** | 36 | `void CreateShip(int16_t, FLEET *32, int16_t, int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FHullHasBombs** | 36 | `int16_t FHullHasBombs(HUL *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FProdIsTerra** | 36 | `int16_t FProdIsTerra(PROD *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **IrcRaceDlgHitTest** | 36 | `int16_t IrcRaceDlgHitTest(POINT)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **LSaltFromSz** | 37 | `int32_t LSaltFromSz(char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **MarkPlayersThatSentMsgs** | 37 | `void MarkPlayersThatSentMsgs(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **ReadBigBlock** | 37 | `int16_t ReadBigBlock(int16_t, char *32, uint32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **WtFromLpfl** | 37 | `int32_t WtFromLpfl(FLEET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **CreateBackupDir** | 38 | `void CreateBackupDir(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **HfontPrinterCreate** | 38 | `uint16_t HfontPrinterCreate(uint16_t, int16_t, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **ICompFleetPoint** | 38 | `int16_t ICompFleetPoint(void *, void *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **InitBattlePlan** | 38 | `void InitBattlePlan(BTLPLAN *32, int16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **PszGetLine** | 38 | `char *32 PszGetLine(char *32 *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DrawFuzzyBorder** | 39 | `void DrawFuzzyBorder(uint16_t, RECT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FAttackPlayer** | 40 | `int16_t FAttackPlayer(FLEET *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FCheckScanner** | 40 | `int16_t FCheckScanner(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **DrawSelectionArrow** | 41 | `void DrawSelectionArrow(uint16_t, RECT *, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **FCheckShipBuilder** | 41 | `int16_t FCheckShipBuilder(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **RcCtrTextOut** | 41 | `void RcCtrTextOut(uint16_t, RECT *, char *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DxOfBtn** | 42 | `int16_t DxOfBtn(int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FillFleetCompLB** | 42 | `void FillFleetCompLB(void)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **AskSaveDialog** | 43 | `int16_t AskSaveDialog(void)` | [file.c](../file.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **DibNumColors** | 43 | `uint16_t DibNumColors(void *32)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **NthValidShdef** | 43 | `SHDEF *32 NthValidShdef(int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **OrderInfoDlg** | 44 | `int16_t OrderInfoDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **PtToScan** | 44 | `int16_t PtToScan(int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ScanToPt** | 44 | `int16_t ScanToPt(int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DrawScanXorLines** | 45 | `void DrawScanXorLines(uint16_t, POINT *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ScoreFromGiveAndTakeAndTactic** | 45 | `int32_t ScoreFromGiveAndTakeAndTactic(int32_t, int32_t, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FGetMouseMove** | 46 | `int16_t FGetMouseMove(POINT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FGetRMouseMove** | 46 | `int16_t FGetRMouseMove(POINT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **HtMsgBox** | 46 | `int16_t HtMsgBox(POINT)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **InvalidateAdvPtsRect** | 46 | `void InvalidateAdvPtsRect(uint16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **FFleetCanJumpgate** | 47 | `int16_t FFleetCanJumpgate(FLEET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **GetDxDyOrientation** | 47 | `void GetDxDyOrientation(int16_t, int16_t, POINT *, POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **MarkFleet** | 47 | `void MarkFleet(FLEET *32, int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **GetASubMenu** | 49 | `uint16_t GetASubMenu(uint16_t, int16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **IntToRoman** | 49 | `void IntToRoman(int16_t, char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **InitTiles** | 50 | `void InitTiles(void)` | [init.c](../init.c) | [init.c](../decompiled/all/init.c) |
| ⬜ | **LFetchScoreXVal** | 50 | `int32_t LFetchScoreXVal(SCOREX *32, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **PanicDlg** | 50 | `int16_t PanicDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **StickyDlgPos** | 50 | `void StickyDlgPos(uint16_t, POINT *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **CommaFormatLong** | 51 | `int16_t CommaFormatLong(char *, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **PctTerraFromLpfl** | 51 | `int32_t PctTerraFromLpfl(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **Delay** | 52 | `void Delay(int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **FCheckSummary** | 52 | `int16_t FCheckSummary(uint16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **HbrGet** | 52 | `uint16_t HbrGet(uint32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **IshFindSimilarDesign** | 52 | `int16_t IshFindSimilarDesign(HUL *32, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FIsTargetOfMdTarget** | 53 | `int16_t FIsTargetOfMdTarget(TOK *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FQueueColonistDrop** | 53 | `int16_t FQueueColonistDrop(FLEET *32, PLANET *32, int32_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **CParseNumbers** | 54 | `int16_t CParseNumbers(char *32, int32_t *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **NthValidEnemyShdef** | 54 | `SHDEF *32 NthValidEnemyShdef(int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FCanMerge** | 55 | `int16_t FCanMerge(FLEET *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **GetVCVal** | 59 | `int16_t GetVCVal(GAME *, int16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **MarkPlanet** | 59 | `void MarkPlanet(PLANET *32, int16_t, uint16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **NewPlanNameDlg** | 59 | `int16_t NewPlanNameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PszGetCompressedString** | 59 | `char * PszGetCompressedString(int16_t)` | [strings.c](../strings.c) | [strings.c](../decompiled/all/strings.c) |
| ⬜ | **NoAutoTrackFleet** | 60 | `void NoAutoTrackFleet(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FOtherStuffAtScanSel** | 62 | `int16_t FOtherStuffAtScanSel(void)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **BoundsCheckPlayer** | 65 | `void BoundsCheckPlayer(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawDiamond** | 65 | `void DrawDiamond(uint16_t, RECT *, uint16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **CshQueued** | 66 | `int16_t CshQueued(int16_t, int16_t *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FIsButtonDown** | 66 | `int16_t FIsButtonDown(int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **HcrsFromFrameWindowPt** | 67 | `uint16_t HcrsFromFrameWindowPt(POINT, int16_t *)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FCheckTemplate** | 69 | `int16_t FCheckTemplate(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FDestIsWP0** | 69 | `int16_t FDestIsWP0(FLEET *32)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FGetNextObjHere** | 69 | `int16_t FGetNextObjHere(SCAN *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **IdmGiveTraderPart** | 72 | `int16_t IdmGiveTraderPart(uint16_t, int16_t, uint16_t *)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **SetHScrollBar** | 73 | `void SetHScrollBar(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **PackageUpMsg** | 75 | `int16_t PackageUpMsg(uint8_t *, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **CPlanetsInCircle** | 76 | `int16_t CPlanetsInCircle(POINT, int32_t)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **DeleteWpFar** | 77 | `void DeleteWpFar(FLEET *32, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FLookupOrbitingXfer** | 80 | `int16_t FLookupOrbitingXfer(int16_t, int16_t, XFER *, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FDoesPrimaryTargetTypeExist** | 92 | `int16_t FDoesPrimaryTargetTypeExist(TOK *32, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **ReadIniTileSettings** | 92 | `void ReadIniTileSettings(char *, TILE *, int16_t)` | [init.c](../init.c) | [init.c](../decompiled/all/init.c) |
| ⬜ | **TerminateToolbarFocus** | 99 | `void TerminateToolbarFocus(int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **SetFilteringGroups** | 112 | `void SetFilteringGroups(int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **LinkFleets** | 113 | `void LinkFleets(int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DiaganolTextOut** | 146 | `void DiaganolTextOut(uint16_t, RECT *, char *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **IValidateWormholePos** | 157 | `int16_t IValidateWormholePos(THING *32)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **FIntersectCircleLine** | 171 | `int16_t FIntersectCircleLine(POINT, POINT, POINT, int32_t, int16_t, int16_t *, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DrawRadarCircle** | 182 | `void DrawRadarCircle(DRAWCIR *, RECT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **InitMDIApp** | 192 | `int16_t InitMDIApp(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **AnimateAttack** | 462 | `void AnimateAttack(uint16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |

### Implemented (52)

<details><summary>Show 52 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | BoundPoints | 43 | [utilgen.c](../utilgen.c) |
| ✅ | BtlDataGet | 54 | [vcr.c](../vcr.c) |
| ✅ | CBattleKills | 54 | [vcr.c](../vcr.c) |
| ✅ | CBattles | 49 | [vcr.c](../vcr.c) |
| ✅ | CchTutorString | 64 | [tutor2.c](../tutor2.c) |
| ✅ | ChFromNybble | 43 | [utilgen.c](../utilgen.c) |
| ✅ | DGetDistance | 30 | [util.c](../util.c) |
| ✅ | FBadFileError | 27 | [file.c](../file.c) |
| ✅ | FBogusLong | 26 | [file.c](../file.c) |
| ✅ | FGetNMsgbig | 64 | [msg.c](../msg.c) |
| ✅ | FShouldPartBeHidden | 92 | [research.c](../research.c) |
| ✅ | FreeHb | 33 | [memory.c](../memory.c) |
| ✅ | GetFileSeeds | 23 | [utilgen.c](../utilgen.c) |
| ✅ | GetMineFieldCounts | 35 | [mine.c](../mine.c) |
| ✅ | GetRaceGrbit | 29 | [race.c](../race.c) |
| ✅ | GetRaceStat | 15 | [race.c](../race.c) |
| ✅ | GetVCCheck | 15 | [create.c](../create.c) |
| ✅ | ICompLong | 15 | [utilgen.c](../utilgen.c) |
| ✅ | IWarpMAFromLppl | 65 | [planet.c](../planet.c) |
| ✅ | IshdefPrimaryFromLpfl | 39 | [util.c](../util.c) |
| ✅ | LGetNextFileXor | 52 | [utilgen.c](../utilgen.c) |
| ✅ | LpengineFromId | 15 | [parts.c](../parts.c) |
| ✅ | LpflFromId | 46 | [util.c](../util.c) |
| ✅ | LphbFromLpHt | 40 | [memory.c](../memory.c) |
| ✅ | LphuldefSBFromId | 15 | [parts.c](../parts.c) |
| ✅ | LpplFromId | 49 | [util.c](../util.c) |
| ✅ | LpplanetaryFromId | 15 | [parts.c](../parts.c) |
| ✅ | LpscannerFromId | 15 | [parts.c](../parts.c) |
| ✅ | LpshdefFromTok | 35 | [battle.c](../battle.c) |
| ✅ | LpshdefSBT | 15 | [parts.c](../parts.c) |
| ✅ | LpshdefT | 15 | [parts.c](../parts.c) |
| ✅ | LpthFromId | 26 | [util.c](../util.c) |
| ✅ | NybbleFromCh | 54 | [utilgen.c](../utilgen.c) |
| ✅ | OutputFileString | 40 | [utilgen.c](../utilgen.c) |
| ✅ | PctPlanetDesirability | 124 | [planet.c](../planet.c) |
| ✅ | PopRandom | 23 | [utilgen.c](../utilgen.c) |
| ✅ | PszCalcGravity | 30 | [planet.c](../planet.c) |
| ✅ | PszGetCompressedMessage | 60 | [msg.c](../msg.c) |
| ✅ | PszGetCompressedPlanet | 75 | [utilgen.c](../utilgen.c) |
| ✅ | PushRandom | 26 | [utilgen.c](../utilgen.c) |
| ✅ | Random | 75 | [utilgen.c](../utilgen.c) |
| ✅ | Randomize | 32 | [utilgen.c](../utilgen.c) |
| ✅ | Randomize2 | 34 | [utilgen.c](../utilgen.c) |
| ✅ | ResetHb | 29 | [memory.c](../memory.c) |
| ✅ | ResetMessages | 27 | [msg.c](../msg.c) |
| ✅ | SetFileSeeds | 17 | [utilgen.c](../utilgen.c) |
| ✅ | SetRaceGrbit | 36 | [race.c](../race.c) |
| ✅ | SetSzWorkFromDt | 53 | [save.c](../save.c) |
| ✅ | StreamClose | 19 | [file.c](../file.c) |
| ✅ | TechStatus | 52 | [parts.c](../parts.c) |
| ✅ | UpdateBattleRecords | 67 | [file.c](../file.c) |
| ✅ | WPackLong | 29 | [util.c](../util.c) |

</details>

## Depth 1 — Calls Only Leaves

### Unimplemented (54)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **GetXferLeftRightRcs** | 21 | `void GetXferLeftRightRcs(RECT *, RECT *, RECT *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **LogicalToScan** | 21 | `void LogicalToScan(POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **PctTrueMaxGrowth** | 23 | `int16_t PctTrueMaxGrowth(int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **WFromLpfl** | 25 | `uint16_t WFromLpfl(FLEET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **PaletteSize** | 26 | `uint16_t PaletteSize(void *32)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **ScanToLogical** | 27 | `void ScanToLogical(POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **SetVCVal** | 29 | `int16_t SetVCVal(GAME *, int16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **ItbFromPpt** | 32 | `int16_t ItbFromPpt(POINT *)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FFleetHasTeeth** | 33 | `int16_t FFleetHasTeeth(FLEET *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FSendPlrMsg** | 35 | `int16_t FSendPlrMsg(int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **MakeNewName** | 35 | `void MakeNewName(char *32)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FSendPrependedPlrMsg** | 37 | `int16_t FSendPrependedPlrMsg(int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FCheckPlanetRoute** | 38 | `int16_t FCheckPlanetRoute(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **GetScanFleetOrientation** | 39 | `void GetScanFleetOrientation(FLEET *32, POINT *, POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DrawLockLight** | 40 | `void DrawLockLight(uint16_t, RECT *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **PszGetDistance** | 41 | `char * PszGetDistance(int16_t, int16_t, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **CMaxDefenses** | 42 | `int16_t CMaxDefenses(PLANET *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FCheckPassword** | 47 | `int16_t FCheckPassword(void)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FCanKillTok** | 51 | `int16_t FCanKillTok(TOK *32, TOK *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PszFromLongK** | 51 | `char * PszFromLongK(int32_t, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **SetScanScrollBars** | 52 | `void SetScanScrollBars(uint16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **HpalFromDib** | 53 | `uint16_t HpalFromDib(uint16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DecorateHullName** | 54 | `void DecorateHullName(int16_t, int16_t, char *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **GetTechLevelCost** | 54 | `int32_t GetTechLevelCost(int16_t, int16_t, int16_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **MarkPlanetsPlayerLost** | 55 | `void MarkPlanetsPlayerLost(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **ShowMainControls** | 55 | `void ShowMainControls(uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **HostOptionsDialog** | 59 | `int16_t HostOptionsDialog(uint16_t, uint16_t, uint16_t, int32_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **SetWindowIniString** | 59 | `void SetWindowIniString(char *, uint16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **RandomSeedDlg** | 66 | `int16_t RandomSeedDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **RandomizeTokOrder** | 66 | `void RandomizeTokOrder(void)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FCheckSelection** | 68 | `int16_t FCheckSelection(uint16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **LDrawGauge** | 71 | `int32_t LDrawGauge(uint16_t, RECT *, int16_t, int32_t *, uint16_t *, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **InvalidateMineralBars** | 72 | `void InvalidateMineralBars(void)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **DrawABunchOfStars** | 78 | `void DrawABunchOfStars(uint16_t, RECT *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **IFindIdealWarp** | 78 | `int16_t IFindIdealWarp(FLEET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **RenameZipDlg** | 80 | `int16_t RenameZipDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **WrapTextOut** | 80 | `void WrapTextOut(uint16_t, int16_t *, int16_t *, char *, int16_t, int16_t, int16_t, int16_t *, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **RenameDlg** | 87 | `int16_t RenameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **InitScoreDlg** | 88 | `void InitScoreDlg(uint16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FPacketDecay** | 90 | `int16_t FPacketDecay(THING *32, int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **SetVisPFFinish** | 90 | `void SetVisPFFinish(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **CTorpHit** | 92 | `int32_t CTorpHit(int32_t, TOK *32, int16_t, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FormatSerialAndEnv** | 97 | `void FormatSerialAndEnv(int32_t, uint8_t *, char *)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FGetSystemColors** | 99 | `int16_t FGetSystemColors(void)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **FValidSerialNo** | 99 | `int16_t FValidSerialNo(char *, int32_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **SortReportCache** | 102 | `void SortReportCache(int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **InitializeMenu** | 112 | `void InitializeMenu(uint16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **GetVCRStats** | 114 | `void GetVCRStats(int16_t, int32_t *, DV *, int32_t *, int16_t *)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **PtDisplayZipOrdInfo** | 132 | `POINT PtDisplayZipOrdInfo(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **RefitFrameChildren** | 146 | `void RefitFrameChildren(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **GetShdefScannerRange** | 207 | `int16_t GetShdefScannerRange(SHDEF *32, int16_t, int16_t *, int16_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawBtn** | 269 | `void DrawBtn(uint16_t, RECT *, int16_t, int16_t, char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **LInnateRaceHabitability** | 277 | `int32_t LInnateRaceHabitability(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **_Draw3dFrame** | ? | `void _Draw3dFrame(uint16_t, RECT *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |

### Implemented (19)

<details><summary>Show 19 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | CchGetString | 27 | [utilgen.c](../utilgen.c) |
| ✅ | FCompressUserString | 65 | [utilgen.c](../utilgen.c) |
| ✅ | FDecompressUserString | 72 | [utilgen.c](../utilgen.c) |
| ✅ | FLookupPart | 393 | [parts.c](../parts.c) |
| ✅ | FValidSerialLong | 50 | [file.c](../file.c) |
| ✅ | FreeLp | 34 | [memory.c](../memory.c) |
| ✅ | GetFileStatus | 20 | [file.c](../file.c) |
| ✅ | GetTruePartCost | 144 | [ship.c](../ship.c) |
| ✅ | HdibLoadBigResource | 43 | [utilgen.c](../utilgen.c) |
| ✅ | IdmGetMessageN | 22 | [msg.c](../msg.c) |
| ✅ | LCalcFuelGainFromRamScoops | 85 | [util.c](../util.c) |
| ✅ | LdpFromItokDv | 54 | [vcr.c](../vcr.c) |
| ✅ | LphuldefFromId | 23 | [parts.c](../parts.c) |
| ✅ | PszCalcEnvVar | 31 | [planet.c](../planet.c) |
| ✅ | PszFleetNameFromWord | 45 | [util.c](../util.c) |
| ✅ | PszGetPlanetName | 30 | [util.c](../util.c) |
| ✅ | SetFileXorStream | 35 | [utilgen.c](../utilgen.c) |
| ✅ | SzVersion | 25 | [util.c](../util.c) |
| ✅ | XorFileBuf | 43 | [utilgen.c](../utilgen.c) |

</details>

## Depth 2 — Calls up to depth 1

### Unimplemented (66)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **FSendPlrMsg2** | 18 | `int16_t FSendPlrMsg2(int16_t, int16_t, int16_t, int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **SetNGWTitle** | 22 | `void SetNGWTitle(uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **SetRCWTitle** | 22 | `void SetRCWTitle(uint16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **PtDisplayString** | 29 | `POINT PtDisplayString(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **FIsPopupHullType** | 30 | `int16_t FIsPopupHullType(int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **FillBattleDD** | 30 | `void FillBattleDD(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FGetBestDefensePart** | 39 | `int16_t FGetBestDefensePart(PART *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **RightTextOut** | 39 | `void RightTextOut(uint16_t, int16_t, int16_t, char *, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DiscoverNewMinerals** | 40 | `void DiscoverNewMinerals(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FFleetHasBombs** | 40 | `int16_t FFleetHasBombs(FLEET *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **IPlrAlsoCheater** | 40 | `int16_t IPlrAlsoCheater(int16_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **DibBlt** | 44 | `int16_t DibBlt(uint16_t, int16_t, int16_t, int16_t, int16_t, uint16_t, int16_t, int16_t, int16_t, int16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FillZipProdLB** | 51 | `void FillZipProdLB(uint16_t, ZIPPRODQ *)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FillBuildPartsLB** | 53 | `void FillBuildPartsLB(uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **StargateRangeFromLppl** | 54 | `int16_t StargateRangeFromLppl(PLANET *32, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawMassWarpGauge** | 56 | `void DrawMassWarpGauge(uint16_t, RECT *, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FCanBuildShdef** | 57 | `int16_t FCanBuildShdef(SHDEF *32, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FDrawTileNC** | 59 | `int16_t FDrawTileNC(uint16_t, TILE *, RECT *, char *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **GetFleetScannerRange** | 59 | `int16_t GetFleetScannerRange(FLEET *32, int16_t *, int16_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **UpdateSlotGlobals** | 59 | `void UpdateSlotGlobals(void)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **CMineFromLpfl** | 63 | `int32_t CMineFromLpfl(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **IdFindAdjStarbase** | 64 | `int16_t IdFindAdjStarbase(int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CostOfDevelopingItem** | 69 | `int32_t CostOfDevelopingItem(char *32)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **FTrackBtn** | 71 | `int16_t FTrackBtn(BTNT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **InitFromHuldef** | 72 | `int16_t InitFromHuldef(HUL *32, int16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FGetNewGameName** | 75 | `int16_t FGetNewGameName(char *)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **DpShieldOfShdef** | 78 | `int32_t DpShieldOfShdef(SHDEF *32, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawTutorText** | 80 | `void DrawTutorText(uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **GetIniWinRc** | 80 | `void GetIniWinRc(char *, char *, int16_t, WN *)` | [init.c](../init.c) | [init.c](../decompiled/all/init.c) |
| ⬜ | **PtDisplayResourceInfo** | 80 | `POINT PtDisplayResourceInfo(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **DrawThingGauge** | 81 | `void DrawThingGauge(uint16_t, RECT *, THING *32, int16_t)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **CMineSweepFromLphul** | 82 | `int32_t CMineSweepFromLphul(HUL *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FCreateFonts** | 82 | `int16_t FCreateFonts(uint16_t)` | [init.c](../init.c) | [init.c](../decompiled/all/init.c) |
| ⬜ | **CPtsCloakFromLphs** | 85 | `int16_t CPtsCloakFromLphs(HS *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **CShipsScanVis** | 86 | `int32_t CShipsScanVis(FLEET *32)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FMatchTarget** | 88 | `int16_t FMatchTarget(FLEET *32, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **PctJammerFromHul** | 92 | `int16_t PctJammerFromHul(HUL *32)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **PszNameProdItem** | 95 | `char * PszNameProdItem(PROD *32)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **DrawPlanShip** | 101 | `void DrawPlanShip(uint16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CLayMinesFromLpfl** | 102 | `int32_t CLayMinesFromLpfl(FLEET *32, int16_t, int16_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **PtDisplayFactoryMineInfo** | 105 | `POINT PtDisplayFactoryMineInfo(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **About** | 106 | `int16_t About(uint16_t, uint16_t, uint16_t, int32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **InvalidateReport** | 106 | `void InvalidateReport(int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **DecorateMsgTitleBar** | 109 | `void DecorateMsgTitleBar(uint16_t, RECT *)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **UpdateShdefCost** | 111 | `void UpdateShdefCost(SHDEF *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **GetDiskSerialNumber** | 114 | `uint32_t GetDiskSerialNumber(void)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **MarkTechsSeen** | 116 | `void MarkTechsSeen(HUL *32, int16_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **MdCalcStargateDamage** | 121 | `int16_t MdCalcStargateDamage(int16_t, int16_t, int16_t, int16_t, int16_t *)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FSerialAndEnvFromSz** | 123 | `int16_t FSerialAndEnvFromSz(int32_t *, uint8_t *, char *)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **KillUsedWaypoints** | 140 | `void KillUsedWaypoints(void)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DxReportColHdr** | 145 | `int16_t DxReportColHdr(int16_t, int16_t, char *, uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **HealShips** | 145 | `void HealShips(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DibFromBitmap** | 173 | `uint16_t DibFromBitmap(uint16_t, uint32_t, uint16_t, uint16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **InitNewGamePlr** | 183 | `void InitNewGamePlr(int16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **DpFromPtokBrcToBrc** | 184 | `int32_t DpFromPtokBrcToBrc(TOK *32, uint8_t, uint8_t, TOK *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PszGetTaskName** | 200 | `char * PszGetTaskName(FLEET *32, int16_t *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FCanTerraformLppl** | 201 | `int16_t FCanTerraformLppl(PLANET *32, int16_t *, int16_t *, int16_t *, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FreeStuff** | 201 | `void FreeStuff(void)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **TooltipWndProc** | 223 | `int32_t TooltipWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FCalcFleetBombDamage** | 238 | `int16_t FCalcFleetBombDamage(FLEET *32, int32_t *, int32_t *, int32_t *, int32_t *, int32_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **CplrBattle** | 300 | `int16_t CplrBattle(FLEET *32, uint16_t *, uint16_t *, uint16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PtDisplayPlanetStateInfo** | 314 | `POINT PtDisplayPlanetStateInfo(uint16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **WriteIniSettings** | 326 | `void WriteIniSettings(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **CAdvantagePoints** | 355 | `int16_t CAdvantagePoints(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawShipScanPath** | 370 | `void DrawShipScanPath(uint16_t, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **GetProductionCosts** | 414 | `void GetProductionCosts(PLANET *32, PROD *32, uint32_t *, int16_t, int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |

### Implemented (10)

<details><summary>Show 10 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | CBattleUnits | 82 | [vcr.c](../vcr.c) |
| ✅ | FLookupPartX | 21 | [parts.c](../parts.c) |
| ✅ | FreePl | 17 | [memory.c](../memory.c) |
| ✅ | IMsgNext | 39 | [msg.c](../msg.c) |
| ✅ | IMsgPrev | 41 | [msg.c](../msg.c) |
| ✅ | LookupBestPlanetaryScanner | 30 | [parts.c](../parts.c) |
| ✅ | OutputSz | 35 | [util.c](../util.c) |
| ✅ | PszPlayerName | 84 | [util.c](../util.c) |
| ✅ | UnpackBattlePlan | 38 | [file.c](../file.c) |
| ✅ | WtMaxShdefStat | 60 | [ship.c](../ship.c) |

</details>

## Depth 3 — Calls up to depth 2

### Unimplemented (53)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **DrawShipPlanet** | 9 | `void DrawShipPlanet(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **CheckInitiative** | 25 | `void CheckInitiative(TOK *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **AlertSz** | 36 | `int16_t AlertSz(char *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DrawMineralItem** | 36 | `void DrawMineralItem(uint16_t, int16_t, int16_t, int16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **IpctCanTerraformLppl** | 37 | `int16_t IpctCanTerraformLppl(PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CMineSweepFromLpfl** | 38 | `int32_t CMineSweepFromLpfl(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **RegenShield** | 40 | `void RegenShield(TOK *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **SetFleetDropDownSel** | 42 | `void SetFleetDropDownSel(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FCheckMessages** | 54 | `int16_t FCheckMessages(int16_t, int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **UninhabitPlanet** | 60 | `void UninhabitPlanet(PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **PctPlanetOptValue** | 62 | `int16_t PctPlanetOptValue(PLANET *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **GetCachedFleetScannerRange** | 65 | `int16_t GetCachedFleetScannerRange(FLEET *32, int16_t *, int16_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **TossNonAutoBuildItems** | 65 | `void TossNonAutoBuildItems(PLANET *32)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FillProdSrcLB** | 66 | `void FillProdSrcLB(uint16_t, int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **DrawBitmapButton** | 68 | `void DrawBitmapButton(uint16_t, POINT, int16_t, int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FSendPlrMsg2XGen** | 71 | `int16_t FSendPlrMsg2XGen(int16_t, int16_t, int16_t, int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **RestoreGameState** | 72 | `void RestoreGameState(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **CheckTarget** | 73 | `void CheckTarget(TOK *32, FLEET *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **AutoFleetOrder** | 75 | `void AutoFleetOrder(FLEET *32, PLANET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DrawDlgLBEntireItem** | 78 | `void DrawDlgLBEntireItem(DRAWITEMSTRUCT *32, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DrawProgressGauge** | 79 | `void DrawProgressGauge(uint16_t, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **ReflowColumn** | 83 | `void ReflowColumn(int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **AutoTerraform** | 84 | `void AutoTerraform(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DrawRaceAdvantagePoints** | 85 | `void DrawRaceAdvantagePoints(uint16_t, RECT *, PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **GetPlanetScannerRange** | 88 | `int16_t GetPlanetScannerRange(PLANET *32, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **IBestTerraform** | 88 | `int16_t IBestTerraform(PLANET *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ITechLearnATech** | 90 | `int16_t ITechLearnATech(int16_t, int16_t, int16_t, int16_t, uint16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PctCloakFromHuldef** | 94 | `int16_t PctCloakFromHuldef(HUL *32, int16_t, int16_t *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawPlanetXferSide** | 110 | `void DrawPlanetXferSide(uint16_t, RECT *, PLANET *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawFleetBitmap** | 111 | `void DrawFleetBitmap(FLEET *32, uint16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawScanFleetCount** | 119 | `void DrawScanFleetCount(FLEET *32, int16_t, int16_t, uint16_t, uint16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DzMoveRangeToConsider** | 120 | `int16_t DzMoveRangeToConsider(TOK *32, uint16_t, uint8_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawNewGame3** | 139 | `void DrawNewGame3(uint16_t, uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **DrawHostDialog2** | 141 | `void DrawHostDialog2(uint16_t, uint16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **PctCloakFromLpfl** | 150 | `int16_t PctCloakFromLpfl(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DrawNewGame2** | 157 | `void DrawNewGame2(uint16_t, uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **SpankTheCheaters** | 171 | `void SpankTheCheaters(void)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **ScoreGuessBattleDamage** | 172 | `int32_t ScoreGuessBattleDamage(TOK *32, uint8_t, int16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawScoreReport** | 176 | `void DrawScoreReport(uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FillBuildDD** | 185 | `void FillBuildDD(uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **ShowTooltip** | 189 | `void ShowTooltip(int16_t, RECT *)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **DrawProductionItem** | 203 | `void DrawProductionItem(uint16_t, RECT *, char *, int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CreateChildWindows** | 204 | `void CreateChildWindows(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **ValidateWaypoints** | 208 | `void ValidateWaypoints(void)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawVCReport** | 214 | `void DrawVCReport(uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CheckWeapons** | 221 | `void CheckWeapons(TOK *32, int16_t *, uint8_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **SetMsgTitle** | 221 | `void SetMsgTitle(uint16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **DrawPlanetStarbase** | 228 | `void DrawPlanetStarbase(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **NewGameDlg** | 235 | `int16_t NewGameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **DrawBuildSelComp** | 241 | `void DrawBuildSelComp(uint16_t, uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DrawHistoryReport** | 302 | `void DrawHistoryReport(uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CreateRandomRace** | 354 | `void CreateRandomRace(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawResearchDlg** | 981 | `void DrawResearchDlg(uint16_t, uint16_t, RECT *, int16_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |

### Implemented (6)

<details><summary>Show 6 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | EstFuelUse | 229 | [ship.c](../ship.c) |
| ✅ | FReadShDef | 157 | [file.c](../file.c) |
| ✅ | LGetFleetStat | 42 | [ship.c](../ship.c) |
| ✅ | PszGetFleetName | 74 | [util.c](../util.c) |
| ✅ | PszGetThingName | 76 | [util.c](../util.c) |
| ✅ | ReadRtPlr | 55 | [file.c](../file.c) |

</details>

## Depth 4 — Calls up to depth 3

### Unimplemented (42)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **DrawFleetComp** | 9 | `void DrawFleetComp(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DirtyGame** | 18 | `void DirtyGame(int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **GetFuelFree** | 20 | `int32_t GetFuelFree(FLEET *32)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **GetCargoFree** | 30 | `int32_t GetCargoFree(FLEET *32)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **EndTutor** | 33 | `void EndTutor(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **SetPlanetTitleBar** | 33 | `void SetPlanetTitleBar(uint16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawToolbar** | 36 | `void DrawToolbar(uint16_t, RECT *)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **UpdateProgressGauge** | 38 | `void UpdateProgressGauge(int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DrawCBEntireItem** | 50 | `void DrawCBEntireItem(DRAWITEMSTRUCT *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FTrackNewGameDlg3** | 54 | `int16_t FTrackNewGameDlg3(uint16_t, POINT, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **ProgressGaugeDlg** | 62 | `int16_t ProgressGaugeDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **PlanetaryClimateChange** | 67 | `void PlanetaryClimateChange(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **IBestRemoteTerra** | 69 | `int16_t IBestRemoteTerra(PLANET *32, int16_t, int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FillShipDD** | 73 | `void FillShipDD(int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawThingXferSide** | 80 | `void DrawThingXferSide(uint16_t, RECT *, THING *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **EnsureTileSize** | 85 | `void EnsureTileSize(int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **SetMineralTitleBar** | 87 | `void SetMineralTitleBar(uint16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **DrawFleetShipsXferSide** | 92 | `void DrawFleetShipsXferSide(uint16_t, RECT *, FLEET *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FuelFleets** | 109 | `void FuelFleets(void)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **DrawPlanShipBitmap** | 113 | `void DrawPlanShipBitmap(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawFleetGauge** | 133 | `void DrawFleetGauge(uint16_t, RECT *, FLEET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **AutoRouteFleet** | 143 | `void AutoRouteFleet(FLEET *32, PLANET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **RaceWizardDlg6** | 146 | `int16_t RaceWizardDlg6(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **SetVCRBoard** | 146 | `int16_t SetVCRBoard(int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **DrawRace3** | 148 | `void DrawRace3(uint16_t, uint16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **RaceWizardDlg4** | 153 | `int16_t RaceWizardDlg4(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **RaceWizardDlg5** | 168 | `int16_t RaceWizardDlg5(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **MeteorStrike** | 170 | `void MeteorStrike(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **UpdateOrdersDDs** | 179 | `void UpdateOrdersDDs(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **PopupMenu** | 206 | `int16_t PopupMenu(uint16_t, int16_t, int16_t, int16_t, int32_t *, char * *, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **SetVisPFInit** | 241 | `void SetVisPFInit(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **SweepForMines** | 248 | `void SweepForMines(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DrawRace2** | 258 | `void DrawRace2(uint16_t, uint16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **SetVisPFThings** | 261 | `void SetVisPFThings(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **DrawSlotDlg** | 291 | `void DrawSlotDlg(uint16_t, uint16_t, RECT *, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DxyMoveTokTo** | 291 | `int16_t DxyMoveTokTo(TOK *32, int16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **RaceWizardDlg1** | 347 | `int16_t RaceWizardDlg1(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **SetVisPFFleets** | 347 | `void SetVisPFFleets(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **SendBattleMessages** | 522 | `void SendBattleMessages(FLEET *32, int16_t, int16_t, uint16_t *, int16_t, int16_t, int16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawVCR** | 616 | `void DrawVCR(uint16_t, int16_t, int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **DrawScanner** | 1316 | `int16_t DrawScanner(uint16_t, RECT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DisplayComponentInfo** | 1495 | `void DisplayComponentInfo(uint16_t, int16_t, int16_t, PART *)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |

### Implemented (4)

<details><summary>Show 4 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | FReadPlanet | 238 | [file.c](../file.c) |
| ✅ | LFuelUseToWaypoint | 133 | [ship.c](../ship.c) |
| ✅ | PszGetLocName | 39 | [util.c](../util.c) |
| ✅ | SpdOfShip | 155 | [battle.c](../battle.c) |

</details>

## Depth 5 — Calls up to depth 4

### Unimplemented (18)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **DrawPlanetShipList** | 9 | `void DrawPlanetShipList(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawShipCargo** | 9 | `void DrawShipCargo(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ShowProgressGauge** | 22 | `void ShowProgressGauge(void)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **SetOrdersLbSel** | 35 | `void SetOrdersLbSel(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetBuildSelection** | 37 | `void SetBuildSelection(int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FTrackRaceDlg3** | 55 | `int16_t FTrackRaceDlg3(uint16_t, POINT, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **PszGetDestName** | 87 | `char * PszGetDestName(FLEET *32, uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **PopupVCRMenu** | 101 | `int16_t PopupVCRMenu(uint16_t, int16_t, int16_t, uint8_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **ScrollScanner** | 107 | `void ScrollScanner(int16_t, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **LComputePower** | 109 | `int32_t LComputePower(SHDEF *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **RedrawScanSel** | 114 | `void RedrawScanSel(uint16_t, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **RemoteTerraforming** | 118 | `void RemoteTerraforming(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **NewGameDlg3** | 119 | `int16_t NewGameDlg3(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **DrawFleetCargoXferSide** | 129 | `void DrawFleetCargoXferSide(uint16_t, RECT *, FLEET *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ReportColumnPopup** | 162 | `void ReportColumnPopup(POINT, int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FTrackRaceDlg2** | 175 | `int16_t FTrackRaceDlg2(uint16_t, POINT, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawScannerSBar** | 288 | `void DrawScannerSBar(uint16_t, RECT *, SBAR *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **SetVisPFPlanets** | 425 | `void SetVisPFPlanets(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |

### Implemented (1)

<details><summary>Show 1 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | PszFormatString | 316 | [msg.c](../msg.c) |

</details>

## Depth 6 — Calls up to depth 5

### Unimplemented (9)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **PszFormatMessage** | 19 | `char * PszFormatMessage(int16_t, int16_t *32)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **SetVisiblePlanFleet** | 34 | `void SetVisiblePlanFleet(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **ComputeShdefPowers** | 36 | `void ComputeShdefPowers(void)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FillOrdersLB** | 46 | `void FillOrdersLB(void)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawXferDlg** | 54 | `void DrawXferDlg(uint16_t, uint16_t, RECT *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **CtrPointScan** | 83 | `void CtrPointScan(POINT, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **RaceWizardDlg3** | 115 | `int16_t RaceWizardDlg3(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **RaceWizardDlg2** | 199 | `int16_t RaceWizardDlg2(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawBuildSelHull** | 431 | `void DrawBuildSelHull(uint16_t, uint16_t, int16_t, RECT *)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |

### Implemented (1)

<details><summary>Show 1 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | PszFormatIds | 19 | [msg.c](../msg.c) |

</details>

## Depth 7 — Calls up to depth 6

### Unimplemented (12)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **RgToStream** | 25 | `void RgToStream(void *32, uint16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **TurnLog** | 25 | `void TurnLog(int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FAskKillTutor** | 28 | `int16_t FAskKillTutor(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **PszGetMessageN** | 29 | `char * PszGetMessageN(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **TutorError** | 35 | `void TutorError(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **WriteMemRt** | 46 | `void WriteMemRt(int16_t, int16_t, void *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FEnsurePointOnScreen** | 58 | `int16_t FEnsurePointOnScreen(POINT, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **TutorDlg** | 87 | `int16_t TutorDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FDeleteBattlePlan** | 89 | `int16_t FDeleteBattlePlan(int16_t, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PasswordDlg** | 90 | `int16_t PasswordDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **MsgDlg** | 99 | `int16_t MsgDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **PrintMapDlg** | 163 | `int16_t PrintMapDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |

### Implemented (3)

<details><summary>Show 3 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | FileError | 24 | [file.c](../file.c) |
| ✅ | LphbAlloc | 61 | [memory.c](../memory.c) |
| ✅ | LphbReAlloc | 82 | [memory.c](../memory.c) |

</details>

## Depth 8 — Calls up to depth 7

### Unimplemented (12)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **LogSplitFleet** | 27 | `void LogSplitFleet(int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FOKMergeDialog** | 32 | `int16_t FOKMergeDialog(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **WriteRt** | 32 | `void WriteRt(int16_t, int16_t, void *32)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **LogMergeFleet** | 34 | `void LogMergeFleet(int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **LogMakeValidXferf** | 49 | `void LogMakeValidXferf(LOGXFERF *, LOGXFERF *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FCheckFleetName** | 57 | `int16_t FCheckFleetName(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckBuilderPart** | 60 | `int16_t FCheckBuilderPart(int16_t, HS *, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckCargo** | 63 | `int16_t FCheckCargo(FLEET *32, int16_t, int16_t, int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckZip** | 66 | `int16_t FCheckZip(int16_t, ITEMACTION *32, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckQueue** | 81 | `int16_t FCheckQueue(int16_t, int16_t, uint16_t, uint16_t, uint16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckFleetWP** | 91 | `int16_t FCheckFleetWP(uint16_t, int16_t, uint16_t, int16_t, uint16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **LogMakeValidXfer** | 168 | `void LogMakeValidXfer(LOGXFER *, LOGXFER *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |

### Implemented (3)

<details><summary>Show 3 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | LpAlloc | 73 | [memory.c](../memory.c) |
| ✅ | RgFromStream | 31 | [file.c](../file.c) |
| ✅ | StreamOpen | 47 | [file.c](../file.c) |

</details>

## Depth 9 — Calls up to depth 8

### Unimplemented (23)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **WriteRtString** | 35 | `void WriteRtString(char *32)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **WriteOrders** | 37 | `void WriteOrders(FLEET *32)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **WriteBOF** | 42 | `void WriteBOF(int16_t, int16_t, int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **WriteBattlePlan** | 48 | `void WriteBattlePlan(BTLPLAN *32, int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **FCheckColonizeWP** | 52 | `int16_t FCheckColonizeWP(uint16_t, int16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckLayingWP** | 52 | `int16_t FCheckLayingWP(uint16_t, int16_t, int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FSetUpBatchProcessing** | 53 | `int16_t FSetUpBatchProcessing(void)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **FCheckPatrolWP** | 54 | `int16_t FCheckPatrolWP(uint16_t, int16_t, int16_t, uint16_t, uint16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **LogChangeThing** | 58 | `void LogChangeThing(THING *32, THING *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **WritePlayerMessages** | 61 | `void WritePlayerMessages(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **CopyFile** | 66 | `void CopyFile(char *, char *)` |  | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **WriteRtPlr** | 66 | `void WriteRtPlr(PLAYER *, uint8_t *)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **WriteRtShDef** | 75 | `void WriteRtShDef(SHDEF *32, uint8_t * *)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **DumpUniverse** | 85 | `void DumpUniverse(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FCheckXferWP** | 98 | `int16_t FCheckXferWP(uint16_t, int16_t, int16_t, uint16_t, ITEMACTION *32)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FWriteTutorialMFile** | 105 | `int16_t FWriteTutorialMFile(int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **LogChangePlanet** | 154 | `void LogChangePlanet(PLANET *32, PLANET *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **WritePlanet** | 177 | `void WritePlanet(PLANET *32, int16_t, int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **LogChangeFleet** | 188 | `void LogChangeFleet(FLEET *32, FLEET *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **WriteBattles** | 244 | `void WriteBattles(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **FTutorialEnabledShipBuilder** | 250 | `int16_t FTutorialEnabledShipBuilder(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCreateStuff** | 283 | `int16_t FCreateStuff(void)` | [init.c](../init.c) | [init.c](../decompiled/all/init.c) |
| ⬜ | **ReadIniSettings** | 513 | `void ReadIniSettings(void)` | [init.c](../init.c) | [init.c](../decompiled/all/init.c) |

### Implemented (3)

<details><summary>Show 3 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | LpReAlloc | 52 | [memory.c](../memory.c) |
| ✅ | LpplAlloc | 26 | [memory.c](../memory.c) |
| ✅ | ReadRt | 29 | [file.c](../file.c) |

</details>

## Depth 10 — Calls up to depth 9

### Unimplemented (10)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **FCreateFile** | 36 | `int16_t FCreateFile(uint16_t, int16_t, char *)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **InitInstance** | 58 | `int16_t InitInstance(int16_t)` | [init.c](../init.c) | [init.c](../decompiled/all/init.c) |
| ⬜ | **LpthNew** | 85 | `THING *32 LpthNew(int16_t, int16_t)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **LpflNew** | 103 | `FLEET *32 LpflNew(int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FWasRaceFile** | 121 | `int16_t FWasRaceFile(char *, int16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **WriteFleet** | 154 | `void WriteFleet(FLEET *32)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **FFinishPlrMsgEntry** | 192 | `int16_t FFinishPlrMsgEntry(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FLoadLogFile** | 192 | `int16_t FLoadLogFile(char *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FMarkFile** | 193 | `int16_t FMarkFile(uint16_t, int16_t, int16_t, int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **FTutorTaskDone** | 3196 | `int16_t FTutorTaskDone(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |

### Implemented (4)

<details><summary>Show 4 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | FOpenFile | 197 | [file.c](../file.c) |
| ✅ | FReadFleet | 215 | [file.c](../file.c) |
| ✅ | LpplReAlloc | 19 | [memory.c](../memory.c) |
| ✅ | ReadPlayerMessages | 98 | [msg.c](../msg.c) |

</details>

## Depth 11 — Calls up to depth 10

### Unimplemented (12)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **FAppendFile** | 21 | `int16_t FAppendFile(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **LpflNewSplit** | 50 | `FLEET *32 LpflNewSplit(FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FDupFleet** | 64 | `int16_t FDupFleet(FLEET *32, FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **AdvanceTutor** | 67 | `void AdvanceTutor(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FDupPlanet** | 68 | `int16_t FDupPlanet(PLANET *32, PLANET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FCheckLogFile** | 76 | `int16_t FCheckLogFile(int16_t, int16_t *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CreateStartupShip** | 78 | `int16_t CreateStartupShip(int16_t, int16_t, int16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **FSaveRace** | 81 | `int16_t FSaveRace(char *, PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **FWriteLogFile** | 90 | `int16_t FWriteLogFile(char *, int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **MysteryTrader** | 117 | `void MysteryTrader(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FWriteHistFile** | 130 | `int16_t FWriteHistFile(int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DropSalvage** | 160 | `void DropSalvage(THING *32 *, int32_t *32, int16_t, POINT *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |

### Implemented (2)

<details><summary>Show 2 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | FCheckFile | 76 | [file.c](../file.c) |
| ✅ | FNewTurnAvail | 36 | [file.c](../file.c) |

</details>

## Depth 12 — Calls up to depth 11

### Unimplemented (20)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **RandomEvents** | 19 | `void RandomEvents(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **LogChangeBtlplan** | 20 | `void LogChangeBtlplan(BTLPLAN *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **LogChangeRelations** | 28 | `void LogChangeRelations(void)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **PromptSaveGame** | 36 | `void PromptSaveGame(void)` | [file.c](../file.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **LogChangeShDef** | 43 | `void LogChangeShDef(SHDEF *32)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FLookupThing** | 60 | `int16_t FLookupThing(int16_t, THING *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FDumpCargo** | 71 | `int16_t FDumpCargo(FLEET *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **LogChangeName** | 73 | `void LogChangeName(int16_t, int16_t, char *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FLookupFleet** | 83 | `int16_t FLookupFleet(int16_t, FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **CFindTurnsOutstanding** | 96 | `int16_t CFindTurnsOutstanding(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **MergeFleetsDlg** | 98 | `int16_t MergeFleetsDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FLookupPlanet** | 103 | `int16_t FLookupPlanet(int16_t, PLANET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **BattleVCR** | 117 | `void BattleVCR(int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **ScoreXDlg** | 140 | `int16_t ScoreXDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CreateSalvage** | 143 | `void CreateSalvage(FLEET *, THING *32 *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **RaceCreationWizard** | 161 | `int16_t RaceCreationWizard(uint16_t, int16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **IDropPart** | 235 | `int16_t IDropPart(POINT, HS, int16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **BrowserDlg** | 302 | `int16_t BrowserDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **ZipProdDlg** | 316 | `int16_t ZipProdDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **ZipOrderDlg** | 326 | `int16_t ZipOrderDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |

## Depth 13 — Calls up to depth 12

### Unimplemented (13)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **FLookupSelShip** | 23 | `int16_t FLookupSelShip(FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FLookupObject** | 26 | `int16_t FLookupObject(int16_t, int16_t, void *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **CTurnsOutSafe** | 32 | `int16_t CTurnsOutSafe(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FLookupSelPlanet** | 34 | `int16_t FLookupSelPlanet(PLANET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **CalcPlanetMaxPop** | 62 | `int32_t CalcPlanetMaxPop(int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FEnumCalcJettison** | 70 | `int16_t FEnumCalcJettison(void *32, int16_t, int16_t, PLANET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **HtMineWindow** | 117 | `int16_t HtMineWindow(uint16_t, int16_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **RelationsDlg** | 132 | `int16_t RelationsDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **ChgCargo** | 162 | `int32_t ChgCargo(int16_t, int16_t, int16_t, int32_t, void *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **InitializeBoard** | 194 | `void InitializeBoard(FLEET *32, int16_t, uint16_t, uint8_t *, int16_t *, int16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **SimpleNewGameDlg** | 242 | `int16_t SimpleNewGameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **FleetTransferCargoBalance** | 381 | `void FleetTransferCargoBalance(FLEET *, FLEET *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **BattlePlansDlg** | 484 | `int16_t BattlePlansDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |

### Implemented (1)

<details><summary>Show 1 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | DestroyCurGame | 137 | [file.c](../file.c) |

</details>

## Depth 14 — Calls up to depth 13

### Unimplemented (13)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **CMaxFactories** | 37 | `int16_t CMaxFactories(PLANET *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CMaxMines** | 37 | `int16_t CMaxMines(PLANET *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **PctPlanetCapacity** | 40 | `int16_t PctPlanetCapacity(PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **XferSupply** | 51 | `int32_t XferSupply(int16_t, int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FFleetSplitAll** | 58 | `int16_t FFleetSplitAll(FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **UpdateXferBtns** | 71 | `void UpdateXferBtns(void)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SaveGameState** | 78 | `void SaveGameState(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **KillShips** | 90 | `void KillShips(TOK *32, int16_t, int16_t, FLEET *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **BreedColonistsInTransit** | 105 | `void BreedColonistsInTransit(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **TransferToOthers** | 171 | `void TransferToOthers(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **ChgPopFromPlanet** | 189 | `int32_t ChgPopFromPlanet(PLANET *32, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FStargateJump** | 261 | `int16_t FStargateJump(FLEET *32, int16_t, int16_t, int16_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FTravelThroughMineFields** | 586 | `int16_t FTravelThroughMineFields(FLEET *32, int16_t *, THING *32)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |

## Depth 15 — Calls up to depth 14

### Unimplemented (9)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **CMaxOperableDefenses** | 43 | `int16_t CMaxOperableDefenses(PLANET *32, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CMaxOperableFactories** | 51 | `int16_t CMaxOperableFactories(PLANET *32, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CMaxOperableMines** | 51 | `int16_t CMaxOperableMines(PLANET *32, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **UpdatePopulations** | 87 | `void UpdatePopulations(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FSetupXferBtns** | 143 | `int16_t FSetupXferBtns(RECT *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FTrackXfer** | 171 | `int16_t FTrackXfer(uint16_t, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ThingDecay** | 181 | `void ThingDecay(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **PtDisplayPlanetPopInfo** | 264 | `POINT PtDisplayPlanetPopInfo(uint16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **InitProduction** | 355 | `void InitProduction(PROD *)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |

## Depth 16 — Calls up to depth 15

### Unimplemented (6)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **CFactoriesOperating** | 49 | `int16_t CFactoriesOperating(PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CMinesOperating** | 53 | `int16_t CMinesOperating(PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **TransferDlg** | 134 | `int16_t TransferDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawPopup** | 295 | `void DrawPopup(uint16_t, uint16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **Popup** | 307 | `void Popup(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **CBuildProdItem** | 423 | `int16_t CBuildProdItem(PLANET *32, PROD *32, PROD *, int32_t *, int16_t, int16_t *, int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |

### Implemented (2)

<details><summary>Show 2 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | CResourcesAtPlanet | 96 | [planet.c](../planet.c) |
| ✅ | CalcPctSurvive | 67 | [util.c](../util.c) |

</details>

## Depth 17 — Calls up to depth 16

### Unimplemented (11)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **DrawPlanetMinSum** | 9 | `void DrawPlanetMinSum(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **PopupWndProc** | 54 | `int32_t PopupWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **UpdateGuesses** | 89 | `void UpdateGuesses(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **BrowserWndProc** | 152 | `int32_t BrowserWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **CalcPlayerScore** | 191 | `int32_t CalcPlayerScore(int16_t, SCORE *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawPlanetStats** | 279 | `void DrawPlanetStats(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FTrackSlot** | 345 | `int16_t FTrackSlot(uint16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **VCRDlg** | 370 | `int16_t VCRDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **DropColonists** | 465 | `void DropColonists(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DoBombing** | 554 | `void DoBombing(void)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **MoveThings** | 726 | `void MoveThings(int16_t)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |

## Depth 18 — Calls up to depth 17

### Unimplemented (2)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **FakeListProc** | 83 | `int32_t FakeListProc(uint16_t, uint16_t, uint16_t, int32_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **UpdatePlayerScores** | 295 | `void UpdatePlayerScores(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |

## Depth -1 — Cyclic Functions

### Unimplemented (105)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **DrawPlanetProduction** | 9 | `void DrawPlanetProduction(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **GenerateWorld** | 9 | `int16_t GenerateWorld(int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **FakeCEProc** | 26 | `int32_t FakeCEProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FakeComboProc** | 27 | `int32_t FakeComboProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **MineMinerals** | 27 | `void MineMinerals(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **SetScanWp** | 27 | `int16_t SetScanWp(int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DestroyAllIshdefSB** | 32 | `void DestroyAllIshdefSB(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FRunLogFile** | 39 | `int16_t FRunLogFile(void)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ShipBuilder** | 44 | `int16_t ShipBuilder(POINT)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FinishProduction** | 49 | `void FinishProduction(int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FNearAWayPoint** | 50 | `int16_t FNearAWayPoint(POINT, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ProjectedResearchSpending** | 55 | `int32_t ProjectedResearchSpending(int32_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **Merge2Fleets** | 56 | `void Merge2Fleets(FLEET *32, FLEET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FFindSomethingAndSelectIt** | 57 | `int16_t FFindSomethingAndSelectIt(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **DoBattles** | 62 | `void DoBattles(int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DoOrders** | 62 | `void DoOrders(int16_t)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **EnsureAis** | 66 | `void EnsureAis(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FindDlg** | 71 | `int16_t FindDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **InitializeProductionDlg** | 72 | `void InitializeProductionDlg(uint16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FleetOrdersChangeTarget** | 75 | `void FleetOrdersChangeTarget(FLEET *32)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ChangeProduction** | 76 | `int16_t ChangeProduction(int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **KillQueuedMassPackets** | 80 | `void KillQueuedMassPackets(PLANET *32)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **SelectAdjPlanet** | 81 | `void SelectAdjPlanet(int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CreateTutorWorld** | 82 | `void CreateTutorWorld(void)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **KillQueuedShips** | 84 | `void KillQueuedShips(PLANET *32)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **SelectOursAtObject** | 86 | `void SelectOursAtObject(POINT *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **PszProductionETA** | 87 | `char * PszProductionETA(PLANET *32, PLPROD *32, int16_t, int16_t *, int16_t *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **RemoveIshdefFromAllQueues** | 91 | `void RemoveIshdefFromAllQueues(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **PszGetETA** | 96 | `char * PszGetETA(uint16_t, FLEET *32, int16_t *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **DrawReport** | 99 | `void DrawReport(uint16_t, uint16_t, RECT *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FDeleteFleet** | 105 | `int16_t FDeleteFleet(int16_t, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DeleteCurWayPoint** | 107 | `void DeleteCurWayPoint(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SelectAdjFleet** | 108 | `void SelectAdjFleet(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **RestoreSelection** | 111 | `void RestoreSelection(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **VerifyTurns** | 119 | `void VerifyTurns(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FSelectSz** | 122 | `int16_t FSelectSz(char *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **CchGetETA** | 123 | `int16_t CchGetETA(uint16_t, FLEET *32, char *, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FCheckQueuedShip** | 128 | `int16_t FCheckQueuedShip(uint16_t, SHDEF *32, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FFleetMergeAll** | 129 | `int16_t FFleetMergeAll(FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FTrackResearchDlg** | 130 | `int16_t FTrackResearchDlg(uint16_t, int16_t, int16_t, int16_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **ChangeMainObjSel** | 138 | `void ChangeMainObjSel(int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ChangeScanSel** | 141 | `void ChangeScanSel(SCAN *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FCanFleetUseStargates** | 147 | `int16_t FCanFleetUseStargates(FLEET *32, POINT, POINT)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **NewPasswordDlg** | 147 | `int16_t NewPasswordDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FillPlanetProdLB** | 148 | `void FillPlanetProdLB(uint16_t, PLPROD *32, PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **StartTutor** | 150 | `void StartTutor(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **PopupMineralScanChoices** | 153 | `void PopupMineralScanChoices(uint16_t, int16_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **MineWndProc** | 157 | `int32_t MineWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **DestroyAllIshdef** | 160 | `void DestroyAllIshdef(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **InvertPaneBorder** | 160 | `POINT InvertPaneBorder(uint16_t, int16_t, POINT, POINT *)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FAddWayPoint** | 173 | `int16_t FAddWayPoint(POINT, SCAN *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **HostTimerProc** | 184 | `void HostTimerProc(uint16_t, uint16_t, uint16_t, uint32_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **BringUpHostDlg** | 185 | `void BringUpHostDlg(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **DrawProductionDlg** | 189 | `void DrawProductionDlg(uint16_t, uint16_t, RECT *, int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **IWarpBestForWaypoint** | 209 | `int16_t IWarpBestForWaypoint(FLEET *32, ORDER *32)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **EstimateItemProdSched** | 223 | `void EstimateItemProdSched(PLANET *32, PLPROD *32, int16_t, int16_t *, int16_t *)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FOpenGame** | 233 | `int16_t FOpenGame(uint16_t, int16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FFindNearestObject** | 236 | `int16_t FFindNearestObject(POINT, int16_t, SCAN *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **ProductionDlg** | 236 | `int16_t ProductionDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **PlanetClick** | 240 | `void PlanetClick(int16_t, int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **EstMineralsMined** | 245 | `void EstMineralsMined(PLANET *32, int32_t *, int32_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **ClickInPlanetOrders** | 255 | `uint16_t ClickInPlanetOrders(POINT, int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FHandleMeasuringTape** | 260 | `int16_t FHandleMeasuringTape(SCAN *, POINT)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FHandleKey** | 273 | `int16_t FHandleKey(uint16_t, int16_t, int16_t, uint32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **TransferStuff** | 278 | `int16_t TransferStuff(int16_t, int16_t, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ExecuteReportClick** | 282 | `void ExecuteReportClick(POINT, int16_t, int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **DrawShipOrders** | 284 | `void DrawShipOrders(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FDamageTok** | 316 | `int16_t FDamageTok(TOK *32, int16_t, int32_t *, int32_t, uint16_t, int16_t, int32_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DumpFleets** | 334 | `void DumpFleets(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ExecuteButton** | 335 | `void ExecuteButton(int16_t, int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **TbWndProc** | 335 | `int32_t TbWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **HostModeDialog** | 341 | `int16_t HostModeDialog(uint16_t, uint16_t, uint16_t, int32_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **ReportDlg** | 354 | `int32_t ReportDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **TitleWndProc** | 354 | `int32_t TitleWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **UpdateResearchStatus** | 357 | `void UpdateResearchStatus(int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DumpPlanets** | 363 | `void DumpPlanets(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FDoCoolBattle** | 377 | `int16_t FDoCoolBattle(FLEET *32, int16_t, uint16_t *, uint16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **MineClick** | 428 | `void MineClick(int16_t, int16_t, int16_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **Produce** | 431 | `void Produce(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **NewGameWizard** | 441 | `void NewGameWizard(uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **NewGameDlg2** | 489 | `int16_t NewGameDlg2(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **GenNewGameFromFile** | 523 | `int16_t GenNewGameFromFile(char *)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **ResearchDlg** | 525 | `int16_t ResearchDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **ScannerWndProc** | 532 | `int32_t ScannerWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ShipCommandProc** | 557 | `void ShipCommandProc(uint16_t, uint16_t, int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FWriteDataFile** | 563 | `int16_t FWriteDataFile(char *, int16_t, int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **DoThingInteractions** | 570 | `void DoThingInteractions(int16_t)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **FHandleWayPointDrag** | 596 | `int16_t FHandleWayPointDrag(POINT)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FBuildObject** | 607 | `int16_t FBuildObject(PLANET *32, int16_t, int16_t, int16_t, int32_t *)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **ClickInShipOrders** | 673 | `uint16_t ClickInShipOrders(POINT, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FGenerateTurn** | 689 | `int16_t FGenerateTurn(void)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **FrameWndProc** | 710 | `int32_t FrameWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **ProdCommandHandler** | 711 | `void ProdCommandHandler(uint16_t, uint16_t, int32_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **PlanetWndProc** | 731 | `int32_t PlanetWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FAttack** | 787 | `int16_t FAttack(int16_t, int16_t, BTLREC *32, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawReportItem** | 832 | `void DrawReportItem(uint16_t, RECT *, int16_t, int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ICompReport** | 864 | `int16_t ICompReport(void *, void *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **MessageWndProc** | 872 | `int32_t MessageWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FRunLogRecord** | 927 | `int16_t FRunLogRecord(int16_t, int16_t, uint8_t *32)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **MoveFleets** | 943 | `void MoveFleets(void)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **DrawShipWayPtOrders** | 957 | `void DrawShipWayPtOrders(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawMineSurvey** | 1092 | `void DrawMineSurvey(uint16_t, RECT *)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **CommandHandler** | 1268 | `void CommandHandler(uint16_t, uint16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **SlotDlg** | 1292 | `int16_t SlotDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **SatisfyOrders** | 1893 | `void SatisfyOrders(int16_t)` | [turn3.c](../turn3.c) | [turn.c](../decompiled/all/turn.c) |

### Implemented (2)

<details><summary>Show 2 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | FLoadGame | 1389 | [file.c](../file.c) |
| ✅ | WinMain | 338 | [winmain.c](../winmain.c) |

</details>

