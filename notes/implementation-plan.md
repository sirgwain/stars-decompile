# Implementation Plan

Auto-generated cross-reference of call graph depth and implementation status.

*AI functions excluded (103 functions from ai.c, ai2.c, ai3.c, ai4.c, aiu.c, aiutil.c)*

## Summary

| Depth | Label | Total | Implemented | Unimplemented |
|-------|-------|------:|------------:|--------------:|
| 0 | Depth 0 — Leaf Functions | 192 | 130 | 62 |
| 1 | Depth 1 — Calls Only Leaves | 73 | 33 | 40 |
| 2 | Depth 2 | 76 | 25 | 51 |
| 3 | Depth 3 | 59 | 13 | 46 |
| 4 | Depth 4 | 46 | 11 | 35 |
| 5 | Depth 5 | 19 | 2 | 17 |
| 6 | Depth 6 | 10 | 2 | 8 |
| 7 | Depth 7 | 15 | 6 | 9 |
| 8 | Depth 8 | 15 | 8 | 7 |
| 9 | Depth 9 | 26 | 17 | 9 |
| 10 | Depth 10 | 14 | 11 | 3 |
| 11 | Depth 11 | 14 | 9 | 5 |
| 12 | Depth 12 | 20 | 8 | 12 |
| 13 | Depth 13 | 14 | 6 | 8 |
| 14 | Depth 14 | 13 | 3 | 10 |
| 15 | Depth 15 | 9 | 3 | 6 |
| 16 | Depth 16 | 8 | 5 | 3 |
| 17 | Depth 17 | 11 | 0 | 11 |
| 18 | Depth 18 | 2 | 0 | 2 |
| -1 | Depth -1 — Cyclic Functions | 107 | 15 | 92 |
| | **Total** | **743** | **307** | **436** |

## Depth 0 — Leaf Functions

### Unimplemented (62)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **InitBtnTrack** | 27 | W | `void InitBtnTrack(BTNT *, uint16_t, uint16_t, RECT *, int16_t, int16_t, int16_t, int16_t, char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **IrcRaceDlgHitTest** | 28 | W | `int16_t IrcRaceDlgHitTest(POINT)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **MarkPlayersThatSentMsgs** | 28 |  | `void MarkPlayersThatSentMsgs(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **IStargateFromLppl** | 29 |  | `int16_t IStargateFromLppl(PLANET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **CreateBackupDir** | 30 |  | `void CreateBackupDir(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FAttackPlayer** | 30 |  | `int16_t FAttackPlayer(FLEET *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **CreateShip** | 31 |  | `void CreateShip(int16_t, FLEET *32, int16_t, int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DxOfBtn** | 31 | W | `int16_t DxOfBtn(int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **WtFromLpfl** | 31 |  | `int32_t WtFromLpfl(FLEET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **HtMsgBox** | 32 | W | `int16_t HtMsgBox(POINT)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **ICompFleetPoint** | 32 |  | `int16_t ICompFleetPoint(void *, void *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawFuzzyBorder** | 33 | W | `void DrawFuzzyBorder(uint16_t, RECT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DrawSelectionArrow** | 33 | W | `void DrawSelectionArrow(uint16_t, RECT *, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **FCheckScanner** | 33 | W | `int16_t FCheckScanner(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **AskSaveDialog** | 34 |  | `int16_t AskSaveDialog(void)` | [file.c](../file.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **HfontPrinterCreate** | 34 | W | `uint16_t HfontPrinterCreate(uint16_t, int16_t, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FCheckShipBuilder** | 35 | W | `int16_t FCheckShipBuilder(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **NthValidShdef** | 35 |  | `SHDEF *32 NthValidShdef(int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FillFleetCompLB** | 36 | W | `void FillFleetCompLB(void)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **OrderInfoDlg** | 36 | W | `int16_t OrderInfoDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **DrawScanXorLines** | 39 | W | `void DrawScanXorLines(uint16_t, POINT *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FCheckSummary** | 39 | W | `int16_t FCheckSummary(uint16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **GetDxDyOrientation** | 40 | W | `void GetDxDyOrientation(int16_t, int16_t, POINT *, POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ScoreFromGiveAndTakeAndTactic** | 40 |  | `int32_t ScoreFromGiveAndTakeAndTactic(int32_t, int32_t, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FFleetCanJumpgate** | 41 |  | `int16_t FFleetCanJumpgate(FLEET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FGetMouseMove** | 41 | W | `int16_t FGetMouseMove(POINT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FGetRMouseMove** | 41 | W | `int16_t FGetRMouseMove(POINT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **InvalidateAdvPtsRect** | 41 | W | `void InvalidateAdvPtsRect(uint16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **IntToRoman** | 42 |  | `void IntToRoman(int16_t, char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **IshFindSimilarDesign** | 43 |  | `int16_t IshFindSimilarDesign(HUL *32, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **LFetchScoreXVal** | 43 | W | `int32_t LFetchScoreXVal(SCOREX *32, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **PanicDlg** | 43 | W | `int16_t PanicDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **NthValidEnemyShdef** | 44 |  | `SHDEF *32 NthValidEnemyShdef(int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FCanMerge** | 45 |  | `int16_t FCanMerge(FLEET *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FIsTargetOfMdTarget** | 45 |  | `int16_t FIsTargetOfMdTarget(TOK *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **CommaFormatLong** | 46 |  | `int16_t CommaFormatLong(char *, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **Delay** | 46 | W | `void Delay(int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **PctTerraFromLpfl** | 46 |  | `int32_t PctTerraFromLpfl(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FQueueColonistDrop** | 47 |  | `int16_t FQueueColonistDrop(FLEET *32, PLANET *32, int32_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **HcrsFromFrameWindowPt** | 51 | W | `uint16_t HcrsFromFrameWindowPt(POINT, int16_t *)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **NewPlanNameDlg** | 51 | W | `int16_t NewPlanNameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FOtherStuffAtScanSel** | 52 | W | `int16_t FOtherStuffAtScanSel(void)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **CshQueued** | 54 |  | `int16_t CshQueued(int16_t, int16_t *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **NoAutoTrackFleet** | 55 |  | `void NoAutoTrackFleet(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **BoundsCheckPlayer** | 56 |  | `void BoundsCheckPlayer(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **FCheckTemplate** | 57 | W | `int16_t FCheckTemplate(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FGetNextObjHere** | 60 | W | `int16_t FGetNextObjHere(SCAN *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FIsButtonDown** | 60 | W | `int16_t FIsButtonDown(int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FDestIsWP0** | 62 | W | `int16_t FDestIsWP0(FLEET *32)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CPlanetsInCircle** | 64 |  | `int16_t CPlanetsInCircle(POINT, int32_t)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **SetHScrollBar** | 64 | W | `void SetHScrollBar(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **IdmGiveTraderPart** | 68 |  | `int16_t IdmGiveTraderPart(uint16_t, int16_t, uint16_t *)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **DeleteWpFar** | 69 |  | `void DeleteWpFar(FLEET *32, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetFilteringGroups** | 73 |  | `void SetFilteringGroups(int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FLookupOrbitingXfer** | 74 |  | `int16_t FLookupOrbitingXfer(int16_t, int16_t, XFER *, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FDoesPrimaryTargetTypeExist** | 84 |  | `int16_t FDoesPrimaryTargetTypeExist(TOK *32, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **TerminateToolbarFocus** | 93 | W | `void TerminateToolbarFocus(int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **LinkFleets** | 103 |  | `void LinkFleets(int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DiaganolTextOut** | 131 | W | `void DiaganolTextOut(uint16_t, RECT *, char *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FIntersectCircleLine** | 135 |  | `int16_t FIntersectCircleLine(POINT, POINT, POINT, int32_t, int16_t, int16_t *, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DrawRadarCircle** | 163 | W | `void DrawRadarCircle(DRAWCIR *, RECT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **AnimateAttack** | 436 | W | `void AnimateAttack(uint16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |

### Implemented (130)

<details><summary>Show 130 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | AddBackTrailingSpaces | 13 |  | [utilgen.c](../utilgen.c) |
| ✅ | BoundPoints | 38 |  | [utilgen.c](../utilgen.c) |
| ✅ | BtlDataGet | 50 |  | [vcr.c](../vcr.c) |
| ✅ | CBattleKills | 43 |  | [vcr.c](../vcr.c) |
| ✅ | CBattles | 44 |  | [vcr.c](../vcr.c) |
| ✅ | CParseNumbers | 49 |  | [utilgen.c](../utilgen.c) |
| ✅ | CancelMemRt | 14 |  | [log.c](../log.c) |
| ✅ | CchTutorString | 58 |  | [tutor2.c](../tutor2.c) |
| ✅ | ChFromNybble | 33 |  | [utilgen.c](../utilgen.c) |
| ✅ | ChopLastWord | 19 |  | [utilgen.c](../utilgen.c) |
| ✅ | ChopTrailingSpaces | 13 |  | [utilgen.c](../utilgen.c) |
| ✅ | ClearFile | 23 |  | [util.c](../util.c) |
| ✅ | CtrTextOut | 18 | W | [utilgen.c](../utilgen.c) |
| ✅ | DGetDistance | 25 |  | [util.c](../util.c) |
| ✅ | DibNumColors | 34 | W | [utilgen.c](../utilgen.c) |
| ✅ | DpOfLpflIshdef | 26 |  | [util.c](../util.c) |
| ✅ | DrawDiamond | 60 | W | [mine.c](../mine.c) |
| ✅ | DrawHostOptions | 10 | W | [mdi.c](../mdi.c) |
| ✅ | DrawPlanetPrintDot | 20 | W | [util.c](../util.c) |
| ✅ | DxStreamTextOut | 21 | W | [utilgen.c](../utilgen.c) |
| ✅ | DxyFromSpdRound | 22 |  | [battle.c](../battle.c) |
| ✅ | DzFromBrcBrc | 20 |  | [battle.c](../battle.c) |
| ✅ | EnableVCRButtons | 28 | W | [vcr.c](../vcr.c) |
| ✅ | EnableZipBtns | 19 | W | [ship2.c](../ship2.c) |
| ✅ | EnableZipProdBtns | 23 | W | [produce.c](../produce.c) |
| ✅ | EnumLogRts | 27 |  | [log.c](../log.c) |
| ✅ | ExpandRc | 14 |  | [utilgen.c](../utilgen.c) |
| ✅ | FBadFileError | 19 |  | [file.c](../file.c) |
| ✅ | FBogusLong | 18 |  | [file.c](../file.c) |
| ✅ | FCanSplit | 19 |  | [ship.c](../ship.c) |
| ✅ | FCanSplitAll | 24 |  | [ship.c](../ship.c) |
| ✅ | FCheckBtlPlan | 23 | W | [tutor.c](../tutor.c) |
| ✅ | FCheckResearch | 18 | W | [tutor.c](../tutor.c) |
| ✅ | FColonizer | 27 |  | [ship2.c](../ship2.c) |
| ✅ | FFindPlayerMessage | 22 |  | [msg.c](../msg.c) |
| ✅ | FFuelTanker | 17 |  | [battle.c](../battle.c) |
| ✅ | FGetNMsgbig | 58 |  | [msg.c](../msg.c) |
| ✅ | FGetPrevLogRt | 27 |  | [log.c](../log.c) |
| ✅ | FHandleChar | 23 | W | [stars.c](../stars.c) |
| ✅ | FHullHasBombs | 30 |  | [battle.c](../battle.c) |
| ✅ | FHullHasTeeth | 24 |  | [battle.c](../battle.c) |
| ✅ | FProdIsTerra | 29 |  | [planet.c](../planet.c) |
| ✅ | FRemovePlayerMessage | 26 |  | [msg.c](../msg.c) |
| ✅ | FScout | 27 |  | [ship2.c](../ship2.c) |
| ✅ | FShouldPartBeHidden | 73 |  | [research.c](../research.c) |
| ✅ | FStringFitsScreen | 29 | W | [utilgen.c](../utilgen.c) |
| ✅ | FakeEditProc | 17 | W | [ship.c](../ship.c) |
| ✅ | FreeHb | 29 |  | [memory.c](../memory.c) |
| ✅ | FreeHbr | 27 | W | [utilgen.c](../utilgen.c) |
| ✅ | FreeLpth | 14 |  | [thing.c](../thing.c) |
| ✅ | GetASubMenu | 44 | W | [mdi.c](../mdi.c) |
| ✅ | GetFileSeeds | 18 |  | [utilgen.c](../utilgen.c) |
| ✅ | GetMineFieldCounts | 29 |  | [mine.c](../mine.c) |
| ✅ | GetRaceGrbit | 22 |  | [race.c](../race.c) |
| ✅ | GetRaceStat | 10 |  | [race.c](../race.c) |
| ✅ | GetTrueHullCost | 16 |  | [util.c](../util.c) |
| ✅ | GetVCCheck | 10 |  | [create.c](../create.c) |
| ✅ | GetVCVal | 55 |  | [create.c](../create.c) |
| ✅ | GetWindowRc | 21 | W | [mdi.c](../mdi.c) |
| ✅ | HandleFocusState | 18 | W | [planet.c](../planet.c) |
| ✅ | HbrGet | 44 | W | [utilgen.c](../utilgen.c) |
| ✅ | HideProgressGauge | 14 | W | [utilgen.c](../utilgen.c) |
| ✅ | HpalBlackReserved | 28 | W | [utilgen.c](../utilgen.c) |
| ✅ | ICompFleetPoint2 | 26 |  | [util.c](../util.c) |
| ✅ | ICompLong | 10 |  | [utilgen.c](../utilgen.c) |
| ✅ | IEmptyBmpFromGrhst | 21 |  | [build.c](../build.c) |
| ✅ | IRaceChecksum | 19 |  | [race.c](../race.c) |
| ✅ | IValidateWormholePos | 138 |  | [thing.c](../thing.c) |
| ✅ | IWarpMAFromLppl | 55 |  | [planet.c](../planet.c) |
| ✅ | IflFromLpfl | 22 |  | [util.c](../util.c) |
| ✅ | InitBattlePlan | 33 |  | [create.c](../create.c) |
| ✅ | InitMDIApp | 176 | W | [mdi.c](../mdi.c) |
| ✅ | InitNewGame3 | 10 |  | [create.c](../create.c) |
| ✅ | InitTiles | 44 | W | [init.c](../init.c) |
| ✅ | IshdefPrimaryFromLpfl | 34 |  | [util.c](../util.c) |
| ✅ | LDistance2 | 17 |  | [utilgen.c](../utilgen.c) |
| ✅ | LGetNextFileXor | 45 |  | [utilgen.c](../utilgen.c) |
| ✅ | LSaltFromSz | 31 |  | [utilgen.c](../utilgen.c) |
| ✅ | LongFromSerialCh | 21 |  | [util.c](../util.c) |
| ✅ | LpengineFromId | 10 |  | [parts.c](../parts.c) |
| ✅ | LpflFromId | 40 |  | [util.c](../util.c) |
| ✅ | LphbFromLpHt | 29 |  | [memory.c](../memory.c) |
| ✅ | LphuldefSBFromId | 10 |  | [parts.c](../parts.c) |
| ✅ | LpplFromId | 42 |  | [util.c](../util.c) |
| ✅ | LpplanetaryFromId | 10 |  | [parts.c](../parts.c) |
| ✅ | LpplrComp | 10 |  | [create.c](../create.c) |
| ✅ | LpscannerFromId | 10 |  | [parts.c](../parts.c) |
| ✅ | LpshdefFromTok | 27 |  | [battle.c](../battle.c) |
| ✅ | LpshdefSBT | 10 |  | [parts.c](../parts.c) |
| ✅ | LpshdefT | 10 |  | [parts.c](../parts.c) |
| ✅ | LpthFromId | 22 |  | [util.c](../util.c) |
| ✅ | MarkFleet | 42 |  | [save.c](../save.c) |
| ✅ | MarkPlanet | 51 |  | [save.c](../save.c) |
| ✅ | NybbleFromCh | 42 |  | [utilgen.c](../utilgen.c) |
| ✅ | OffsetRc | 14 |  | [utilgen.c](../utilgen.c) |
| ✅ | OutputFileString | 35 |  | [utilgen.c](../utilgen.c) |
| ✅ | PackageUpMsg | 60 |  | [msg.c](../msg.c) |
| ✅ | PctPlanetDesirability | 108 |  | [planet.c](../planet.c) |
| ✅ | PctWormholeMoves | 20 |  | [thing.c](../thing.c) |
| ✅ | PopRandom | 15 |  | [utilgen.c](../utilgen.c) |
| ✅ | PszCalcGravity | 24 |  | [planet.c](../planet.c) |
| ✅ | PszFromInt | 17 |  | [utilgen.c](../utilgen.c) |
| ✅ | PszFromLong | 17 |  | [utilgen.c](../utilgen.c) |
| ✅ | PszGetCompressedMessage | 54 |  | [msg.c](../msg.c) |
| ✅ | PszGetCompressedPlanet | 68 |  | [utilgen.c](../utilgen.c) |
| ✅ | PszGetCompressedString | 54 |  | [strings.c](../strings.c) |
| ✅ | PszGetLine | 34 |  | [utilgen.c](../utilgen.c) |
| ✅ | PtToScan | 39 | W | [scan.c](../scan.c) |
| ✅ | PushRandom | 21 |  | [utilgen.c](../utilgen.c) |
| ✅ | Random | 67 |  | [utilgen.c](../utilgen.c) |
| ✅ | Randomize | 27 |  | [utilgen.c](../utilgen.c) |
| ✅ | Randomize2 | 29 |  | [utilgen.c](../utilgen.c) |
| ✅ | RcCtrTextOut | 35 | W | [utilgen.c](../utilgen.c) |
| ✅ | ReadBigBlock | 32 |  | [utilgen.c](../utilgen.c) |
| ✅ | ReadIniTileSettings | 86 | W | [init.c](../init.c) |
| ✅ | ResetHb | 24 |  | [memory.c](../memory.c) |
| ✅ | ResetMessages | 22 |  | [msg.c](../msg.c) |
| ✅ | ScanToPt | 39 | W | [scan.c](../scan.c) |
| ✅ | SetFileSeeds | 12 |  | [utilgen.c](../utilgen.c) |
| ✅ | SetRaceGrbit | 30 |  | [race.c](../race.c) |
| ✅ | SetRaceStat | 17 |  | [race.c](../race.c) |
| ✅ | SetSzWorkFromDt | 44 |  | [save.c](../save.c) |
| ✅ | SetVCCheck | 18 |  | [create.c](../create.c) |
| ✅ | ShowTutor | 21 | W | [tutor.c](../tutor.c) |
| ✅ | StickyDlgPos | 43 | W | [utilgen.c](../utilgen.c) |
| ✅ | StreamClose | 14 |  | [file.c](../file.c) |
| ✅ | TechStatus | 43 |  | [parts.c](../parts.c) |
| ✅ | UnmarkMineFields | 22 |  | [turn2.c](../turn2.c) |
| ✅ | UpdateBattleRecords | 63 |  | [file.c](../file.c) |
| ✅ | WPackLong | 25 |  | [util.c](../util.c) |

</details>

## Depth 1 — Calls Only Leaves

### Unimplemented (40)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **GetXferLeftRightRcs** | 16 | W | `void GetXferLeftRightRcs(RECT *, RECT *, RECT *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **LogicalToScan** | 16 | W | `void LogicalToScan(POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **WFromLpfl** | 20 |  | `uint16_t WFromLpfl(FLEET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **ScanToLogical** | 22 | W | `void ScanToLogical(POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FSendPrependedPlrMsg** | 26 |  | `int16_t FSendPrependedPlrMsg(int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **MakeNewName** | 26 |  | `void MakeNewName(char *32)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FFleetHasTeeth** | 27 |  | `int16_t FFleetHasTeeth(FLEET *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **ItbFromPpt** | 27 | W | `int16_t ItbFromPpt(POINT *)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FCheckPlanetRoute** | 31 | W | `int16_t FCheckPlanetRoute(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **GetScanFleetOrientation** | 32 | W | `void GetScanFleetOrientation(FLEET *32, POINT *, POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DrawLockLight** | 34 | W | `void DrawLockLight(uint16_t, RECT *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **PszGetDistance** | 34 |  | `char * PszGetDistance(int16_t, int16_t, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FCanKillTok** | 42 |  | `int16_t FCanKillTok(TOK *32, TOK *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PszFromLongK** | 44 |  | `char * PszFromLongK(int32_t, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DecorateHullName** | 46 |  | `void DecorateHullName(int16_t, int16_t, char *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **GetTechLevelCost** | 46 |  | `int32_t GetTechLevelCost(int16_t, int16_t, int16_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **MarkPlanetsPlayerLost** | 48 |  | `void MarkPlanetsPlayerLost(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **ShowMainControls** | 48 | W | `void ShowMainControls(uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **HostOptionsDialog** | 50 | W | `int16_t HostOptionsDialog(uint16_t, uint16_t, uint16_t, int32_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FCheckSelection** | 53 | W | `int16_t FCheckSelection(uint16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **RandomSeedDlg** | 60 | W | `int16_t RandomSeedDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **RandomizeTokOrder** | 61 |  | `void RandomizeTokOrder(void)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **LDrawGauge** | 64 | W | `int32_t LDrawGauge(uint16_t, RECT *, int16_t, int32_t *, uint16_t *, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **InvalidateMineralBars** | 66 | W | `void InvalidateMineralBars(void)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **DrawABunchOfStars** | 68 | W | `void DrawABunchOfStars(uint16_t, RECT *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **IFindIdealWarp** | 68 |  | `int16_t IFindIdealWarp(FLEET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **RenameZipDlg** | 70 | W | `int16_t RenameZipDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **WrapTextOut** | 72 | W | `void WrapTextOut(uint16_t, int16_t *, int16_t *, char *, int16_t, int16_t, int16_t, int16_t *, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **RenameDlg** | 75 | W | `int16_t RenameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FPacketDecay** | 76 |  | `int16_t FPacketDecay(THING *32, int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **CTorpHit** | 79 |  | `int32_t CTorpHit(int32_t, TOK *32, int16_t, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **InitScoreDlg** | 80 | W | `void InitScoreDlg(uint16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FValidSerialNo** | 91 |  | `int16_t FValidSerialNo(char *, int32_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **SortReportCache** | 95 | W | `void SortReportCache(int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **GetVCRStats** | 107 | W | `void GetVCRStats(int16_t, int32_t *, DV *, int32_t *, int16_t *)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **PtDisplayZipOrdInfo** | 127 | W | `POINT PtDisplayZipOrdInfo(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **GetShdefScannerRange** | 184 |  | `int16_t GetShdefScannerRange(SHDEF *32, int16_t, int16_t *, int16_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **LInnateRaceHabitability** | 250 |  | `int32_t LInnateRaceHabitability(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawBtn** | 258 | W | `void DrawBtn(uint16_t, RECT *, int16_t, int16_t, char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **_Draw3dFrame** | ? | W | `void _Draw3dFrame(uint16_t, RECT *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |

### Implemented (33)

<details><summary>Show 33 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CMaxDefenses | 34 |  | [planet.c](../planet.c) |
| ✅ | CchGetString | 22 |  | [utilgen.c](../utilgen.c) |
| ✅ | FCheckPassword | 35 |  | [utilgen.c](../utilgen.c) |
| ✅ | FCompressUserString | 57 |  | [utilgen.c](../utilgen.c) |
| ✅ | FDecompressUserString | 65 |  | [utilgen.c](../utilgen.c) |
| ✅ | FGetSystemColors | 94 | W | [stars.c](../stars.c) |
| ✅ | FLookupPart | 352 |  | [parts.c](../parts.c) |
| ✅ | FSendPlrMsg | 26 |  | [msg.c](../msg.c) |
| ✅ | FValidSerialLong | 41 |  | [file.c](../file.c) |
| ✅ | FormatSerialAndEnv | 87 |  | [mdi.c](../mdi.c) |
| ✅ | FreeLp | 29 |  | [memory.c](../memory.c) |
| ✅ | GetFileStatus | 15 |  | [file.c](../file.c) |
| ✅ | GetTruePartCost | 113 |  | [ship.c](../ship.c) |
| ✅ | HdibLoadBigResource | 38 | W | [utilgen.c](../utilgen.c) |
| ✅ | HpalFromDib | 45 | W | [utilgen.c](../utilgen.c) |
| ✅ | IdmGetMessageN | 17 |  | [msg.c](../msg.c) |
| ✅ | InitializeMenu | 95 | W | [mdi.c](../mdi.c) |
| ✅ | LCalcFuelGainFromRamScoops | 77 |  | [util.c](../util.c) |
| ✅ | LdpFromItokDv | 47 |  | [vcr.c](../vcr.c) |
| ✅ | LphuldefFromId | 17 |  | [parts.c](../parts.c) |
| ✅ | PaletteSize | 20 | W | [utilgen.c](../utilgen.c) |
| ✅ | PctTrueMaxGrowth | 18 |  | [race.c](../race.c) |
| ✅ | PszCalcEnvVar | 25 |  | [planet.c](../planet.c) |
| ✅ | PszFleetNameFromWord | 37 |  | [util.c](../util.c) |
| ✅ | PszGetPlanetName | 24 |  | [util.c](../util.c) |
| ✅ | RefitFrameChildren | 129 | W | [mdi.c](../mdi.c) |
| ✅ | SetFileXorStream | 29 |  | [utilgen.c](../utilgen.c) |
| ✅ | SetScanScrollBars | 44 | W | [scan.c](../scan.c) |
| ✅ | SetVCVal | 23 |  | [create.c](../create.c) |
| ✅ | SetVisPFFinish | 71 |  | [save.c](../save.c) |
| ✅ | SetWindowIniString | 52 | W | [mdi.c](../mdi.c) |
| ✅ | SzVersion | 20 |  | [util.c](../util.c) |
| ✅ | XorFileBuf | 38 |  | [utilgen.c](../utilgen.c) |

</details>

## Depth 2 — Calls up to depth 1

### Unimplemented (51)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **SetNGWTitle** | 17 | W | `void SetNGWTitle(uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **SetRCWTitle** | 17 | W | `void SetRCWTitle(uint16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **FIsPopupHullType** | 22 | W | `int16_t FIsPopupHullType(int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **FillBattleDD** | 23 | W | `void FillBattleDD(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **PtDisplayString** | 23 | W | `POINT PtDisplayString(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **IPlrAlsoCheater** | 27 |  | `int16_t IPlrAlsoCheater(int16_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **DiscoverNewMinerals** | 34 |  | `void DiscoverNewMinerals(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FGetBestDefensePart** | 34 |  | `int16_t FGetBestDefensePart(PART *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FFleetHasBombs** | 35 |  | `int16_t FFleetHasBombs(FLEET *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FillZipProdLB** | 46 | W | `void FillZipProdLB(uint16_t, ZIPPRODQ *)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **StargateRangeFromLppl** | 46 |  | `int16_t StargateRangeFromLppl(PLANET *32, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawMassWarpGauge** | 49 | W | `void DrawMassWarpGauge(uint16_t, RECT *, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FillBuildPartsLB** | 50 | W | `void FillBuildPartsLB(uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **UpdateSlotGlobals** | 50 | W | `void UpdateSlotGlobals(void)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FCanBuildShdef** | 52 |  | `int16_t FCanBuildShdef(SHDEF *32, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FDrawTileNC** | 52 | W | `int16_t FDrawTileNC(uint16_t, TILE *, RECT *, char *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **GetFleetScannerRange** | 53 |  | `int16_t GetFleetScannerRange(FLEET *32, int16_t *, int16_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **IdFindAdjStarbase** | 53 | W | `int16_t IdFindAdjStarbase(int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FTrackBtn** | 61 | W | `int16_t FTrackBtn(BTNT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **InitFromHuldef** | 62 |  | `int16_t InitFromHuldef(HUL *32, int16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **CostOfDevelopingItem** | 64 |  | `int32_t CostOfDevelopingItem(char *32)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **FGetNewGameName** | 67 |  | `int16_t FGetNewGameName(char *)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **CPtsCloakFromLphs** | 69 |  | `int16_t CPtsCloakFromLphs(HS *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DpShieldOfShdef** | 69 |  | `int32_t DpShieldOfShdef(SHDEF *32, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawThingGauge** | 72 |  | `void DrawThingGauge(uint16_t, RECT *, THING *32, int16_t)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **DrawTutorText** | 72 | W | `void DrawTutorText(uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **PtDisplayResourceInfo** | 75 | W | `POINT PtDisplayResourceInfo(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **CMineSweepFromLphul** | 76 |  | `int32_t CMineSweepFromLphul(HUL *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **CShipsScanVis** | 76 | W | `int32_t CShipsScanVis(FLEET *32)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **PszNameProdItem** | 79 |  | `char * PszNameProdItem(PROD *32)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FMatchTarget** | 80 |  | `int16_t FMatchTarget(FLEET *32, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **PctJammerFromHul** | 82 |  | `int16_t PctJammerFromHul(HUL *32)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DrawPlanShip** | 91 | W | `void DrawPlanShip(uint16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CLayMinesFromLpfl** | 92 |  | `int32_t CLayMinesFromLpfl(FLEET *32, int16_t, int16_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **InvalidateReport** | 94 |  | `void InvalidateReport(int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **About** | 96 | W | `int16_t About(uint16_t, uint16_t, uint16_t, int32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **PtDisplayFactoryMineInfo** | 96 | W | `POINT PtDisplayFactoryMineInfo(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **MarkTechsSeen** | 98 |  | `void MarkTechsSeen(HUL *32, int16_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DecorateMsgTitleBar** | 100 | W | `void DecorateMsgTitleBar(uint16_t, RECT *)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **MdCalcStargateDamage** | 116 |  | `int16_t MdCalcStargateDamage(int16_t, int16_t, int16_t, int16_t, int16_t *)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **HealShips** | 124 |  | `void HealShips(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **KillUsedWaypoints** | 125 |  | `void KillUsedWaypoints(void)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DxReportColHdr** | 138 | W | `int16_t DxReportColHdr(int16_t, int16_t, char *, uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **DpFromPtokBrcToBrc** | 161 |  | `int32_t DpFromPtokBrcToBrc(TOK *32, uint8_t, uint8_t, TOK *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PszGetTaskName** | 178 |  | `char * PszGetTaskName(FLEET *32, int16_t *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FCalcFleetBombDamage** | 187 |  | `int16_t FCalcFleetBombDamage(FLEET *32, int32_t *, int32_t *, int32_t *, int32_t *, int32_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **TooltipWndProc** | 208 | W | `int32_t TooltipWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **PtDisplayPlanetStateInfo** | 252 | W | `POINT PtDisplayPlanetStateInfo(uint16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **CplrBattle** | 269 |  | `int16_t CplrBattle(FLEET *32, uint16_t *, uint16_t *, uint16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **CAdvantagePoints** | 315 |  | `int16_t CAdvantagePoints(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawShipScanPath** | 337 | W | `void DrawShipScanPath(uint16_t, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |

### Implemented (25)

<details><summary>Show 25 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CBattleUnits | 71 |  | [vcr.c](../vcr.c) |
| ✅ | CMineFromLpfl | 57 |  | [ship2.c](../ship2.c) |
| ✅ | DibBlt | 34 | W | [utilgen.c](../utilgen.c) |
| ✅ | DibFromBitmap | 158 | W | [utilgen.c](../utilgen.c) |
| ✅ | FCanTerraformLppl | 183 |  | [planet.c](../planet.c) |
| ✅ | FCreateFonts | 77 | W | [init.c](../init.c) |
| ✅ | FLookupPartX | 16 |  | [parts.c](../parts.c) |
| ✅ | FSendPlrMsg2 | 13 |  | [msg.c](../msg.c) |
| ✅ | FSerialAndEnvFromSz | 112 |  | [mdi.c](../mdi.c) |
| ✅ | FreePl | 13 |  | [memory.c](../memory.c) |
| ✅ | FreeStuff | 180 | W | [init.c](../init.c) |
| ✅ | GetDiskSerialNumber | 104 |  | [utilgen.c](../utilgen.c) |
| ✅ | GetIniWinRc | 71 | W | [init.c](../init.c) |
| ✅ | GetProductionCosts | 383 |  | [produce.c](../produce.c) |
| ✅ | IMsgNext | 31 |  | [msg.c](../msg.c) |
| ✅ | IMsgPrev | 32 |  | [msg.c](../msg.c) |
| ✅ | InitNewGamePlr | 140 |  | [create.c](../create.c) |
| ✅ | LookupBestPlanetaryScanner | 25 |  | [parts.c](../parts.c) |
| ✅ | OutputSz | 29 |  | [util.c](../util.c) |
| ✅ | PszPlayerName | 72 |  | [util.c](../util.c) |
| ✅ | RightTextOut | 32 | W | [utilgen.c](../utilgen.c) |
| ✅ | UnpackBattlePlan | 30 |  | [file.c](../file.c) |
| ✅ | UpdateShdefCost | 97 |  | [util.c](../util.c) |
| ✅ | WriteIniSettings | 302 | W | [mdi.c](../mdi.c) |
| ✅ | WtMaxShdefStat | 48 |  | [ship.c](../ship.c) |

</details>

## Depth 3 — Calls up to depth 2

### Unimplemented (46)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **DrawShipPlanet** | 6 | W | `void DrawShipPlanet(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **CheckInitiative** | 20 |  | `void CheckInitiative(TOK *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawMineralItem** | 27 | W | `void DrawMineralItem(uint16_t, int16_t, int16_t, int16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CMineSweepFromLpfl** | 32 |  | `int32_t CMineSweepFromLpfl(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **RegenShield** | 35 |  | `void RegenShield(TOK *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **SetFleetDropDownSel** | 38 | W | `void SetFleetDropDownSel(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FCheckMessages** | 42 | W | `int16_t FCheckMessages(int16_t, int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **UninhabitPlanet** | 51 |  | `void UninhabitPlanet(PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **TossNonAutoBuildItems** | 57 |  | `void TossNonAutoBuildItems(PLANET *32)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DrawBitmapButton** | 59 | W | `void DrawBitmapButton(uint16_t, POINT, int16_t, int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FillProdSrcLB** | 59 | W | `void FillProdSrcLB(uint16_t, int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **CheckTarget** | 61 |  | `void CheckTarget(TOK *32, FLEET *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **RestoreGameState** | 66 | W | `void RestoreGameState(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **AutoFleetOrder** | 69 |  | `void AutoFleetOrder(FLEET *32, PLANET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DrawDlgLBEntireItem** | 71 | W | `void DrawDlgLBEntireItem(DRAWITEMSTRUCT *32, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DrawProgressGauge** | 72 | W | `void DrawProgressGauge(uint16_t, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **AutoTerraform** | 74 |  | `void AutoTerraform(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **ReflowColumn** | 74 | W | `void ReflowColumn(int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **GetPlanetScannerRange** | 75 |  | `int16_t GetPlanetScannerRange(PLANET *32, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **ITechLearnATech** | 75 |  | `int16_t ITechLearnATech(int16_t, int16_t, int16_t, int16_t, uint16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PctCloakFromHuldef** | 77 |  | `int16_t PctCloakFromHuldef(HUL *32, int16_t, int16_t *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawRaceAdvantagePoints** | 79 | W | `void DrawRaceAdvantagePoints(uint16_t, RECT *, PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **IBestTerraform** | 79 |  | `int16_t IBestTerraform(PLANET *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawFleetBitmap** | 98 | W | `void DrawFleetBitmap(FLEET *32, uint16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawPlanetXferSide** | 102 | W | `void DrawPlanetXferSide(uint16_t, RECT *, PLANET *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawScanFleetCount** | 108 | W | `void DrawScanFleetCount(FLEET *32, int16_t, int16_t, uint16_t, uint16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DzMoveRangeToConsider** | 111 |  | `int16_t DzMoveRangeToConsider(TOK *32, uint16_t, uint8_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawNewGame3** | 130 | W | `void DrawNewGame3(uint16_t, uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **PctCloakFromLpfl** | 131 |  | `int16_t PctCloakFromLpfl(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DrawNewGame2** | 137 | W | `void DrawNewGame2(uint16_t, uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **SpankTheCheaters** | 154 |  | `void SpankTheCheaters(void)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawScoreReport** | 155 | W | `void DrawScoreReport(uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ScoreGuessBattleDamage** | 156 |  | `int32_t ScoreGuessBattleDamage(TOK *32, uint8_t, int16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FillBuildDD** | 167 | W | `void FillBuildDD(uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **ShowTooltip** | 179 | W | `void ShowTooltip(int16_t, RECT *)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **ValidateWaypoints** | 182 |  | `void ValidateWaypoints(void)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawProductionItem** | 184 | W | `void DrawProductionItem(uint16_t, RECT *, char *, int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **SetMsgTitle** | 193 | W | `void SetMsgTitle(uint16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **DrawVCReport** | 195 | W | `void DrawVCReport(uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CheckWeapons** | 202 |  | `void CheckWeapons(TOK *32, int16_t *, uint8_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawPlanetStarbase** | 207 | W | `void DrawPlanetStarbase(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawBuildSelComp** | 220 | W | `void DrawBuildSelComp(uint16_t, uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **NewGameDlg** | 223 | W | `int16_t NewGameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **DrawHistoryReport** | 274 | W | `void DrawHistoryReport(uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CreateRandomRace** | 336 |  | `void CreateRandomRace(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawResearchDlg** | 901 | W | `void DrawResearchDlg(uint16_t, uint16_t, RECT *, int16_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |

### Implemented (13)

<details><summary>Show 13 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | AlertSz | 28 | W | [utilgen.c](../utilgen.c) |
| ✅ | CreateChildWindows | 179 | W | [mdi.c](../mdi.c) |
| ✅ | DrawHostDialog2 | 128 | W | [mdi.c](../mdi.c) |
| ✅ | EstFuelUse | 203 |  | [ship.c](../ship.c) |
| ✅ | FReadShDef | 137 |  | [file.c](../file.c) |
| ✅ | FSendPlrMsg2XGen | 55 |  | [msg.c](../msg.c) |
| ✅ | GetCachedFleetScannerRange | 58 |  | [util.c](../util.c) |
| ✅ | IpctCanTerraformLppl | 31 |  | [planet.c](../planet.c) |
| ✅ | LGetFleetStat | 34 |  | [ship.c](../ship.c) |
| ✅ | PctPlanetOptValue | 52 |  | [planet.c](../planet.c) |
| ✅ | PszGetFleetName | 63 |  | [util.c](../util.c) |
| ✅ | PszGetThingName | 63 |  | [util.c](../util.c) |
| ✅ | ReadRtPlr | 44 |  | [file.c](../file.c) |

</details>

## Depth 4 — Calls up to depth 3

### Unimplemented (35)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **DrawFleetComp** | 6 | W | `void DrawFleetComp(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetPlanetTitleBar** | 26 | W | `void SetPlanetTitleBar(uint16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **EndTutor** | 27 | W | `void EndTutor(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **DrawToolbar** | 31 | W | `void DrawToolbar(uint16_t, RECT *)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **DrawCBEntireItem** | 44 | W | `void DrawCBEntireItem(DRAWITEMSTRUCT *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FTrackNewGameDlg3** | 47 | W | `int16_t FTrackNewGameDlg3(uint16_t, POINT, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **ProgressGaugeDlg** | 53 | W | `int16_t ProgressGaugeDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **PlanetaryClimateChange** | 60 |  | `void PlanetaryClimateChange(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **IBestRemoteTerra** | 65 |  | `int16_t IBestRemoteTerra(PLANET *32, int16_t, int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FillShipDD** | 66 | W | `void FillShipDD(int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawThingXferSide** | 73 | W | `void DrawThingXferSide(uint16_t, RECT *, THING *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetMineralTitleBar** | 73 | W | `void SetMineralTitleBar(uint16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **EnsureTileSize** | 79 | W | `void EnsureTileSize(int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawFleetShipsXferSide** | 83 | W | `void DrawFleetShipsXferSide(uint16_t, RECT *, FLEET *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FuelFleets** | 92 |  | `void FuelFleets(void)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **DrawPlanShipBitmap** | 99 | W | `void DrawPlanShipBitmap(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawFleetGauge** | 109 | W | `void DrawFleetGauge(uint16_t, RECT *, FLEET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetVCRBoard** | 131 | W | `int16_t SetVCRBoard(int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **AutoRouteFleet** | 133 |  | `void AutoRouteFleet(FLEET *32, PLANET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **RaceWizardDlg6** | 134 | W | `int16_t RaceWizardDlg6(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawRace3** | 137 | W | `void DrawRace3(uint16_t, uint16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **RaceWizardDlg4** | 144 | W | `int16_t RaceWizardDlg4(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **UpdateOrdersDDs** | 152 | W | `void UpdateOrdersDDs(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **RaceWizardDlg5** | 155 | W | `int16_t RaceWizardDlg5(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **MeteorStrike** | 157 |  | `void MeteorStrike(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **PopupMenu** | 182 | W | `int16_t PopupMenu(uint16_t, int16_t, int16_t, int16_t, int32_t *, char * *, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **DrawRace2** | 225 | W | `void DrawRace2(uint16_t, uint16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **SweepForMines** | 231 |  | `void SweepForMines(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DrawSlotDlg** | 257 | W | `void DrawSlotDlg(uint16_t, uint16_t, RECT *, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DxyMoveTokTo** | 263 |  | `int16_t DxyMoveTokTo(TOK *32, int16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **RaceWizardDlg1** | 336 | W | `int16_t RaceWizardDlg1(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **SendBattleMessages** | 424 |  | `void SendBattleMessages(FLEET *32, int16_t, int16_t, uint16_t *, int16_t, int16_t, int16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawVCR** | 536 | W | `void DrawVCR(uint16_t, int16_t, int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **DrawScanner** | 1198 | W | `int16_t DrawScanner(uint16_t, RECT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DisplayComponentInfo** | 1327 | W | `void DisplayComponentInfo(uint16_t, int16_t, int16_t, PART *)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |

### Implemented (11)

<details><summary>Show 11 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | DirtyGame | 13 |  | [log.c](../log.c) |
| ✅ | FReadPlanet | 207 |  | [file.c](../file.c) |
| ✅ | GetCargoFree | 25 |  | [ship.c](../ship.c) |
| ✅ | GetFuelFree | 15 |  | [ship.c](../ship.c) |
| ✅ | LFuelUseToWaypoint | 116 |  | [ship.c](../ship.c) |
| ✅ | PszGetLocName | 33 |  | [util.c](../util.c) |
| ✅ | SetVisPFFleets | 319 |  | [save.c](../save.c) |
| ✅ | SetVisPFInit | 197 |  | [save.c](../save.c) |
| ✅ | SetVisPFThings | 229 |  | [save.c](../save.c) |
| ✅ | SpdOfShip | 137 |  | [battle.c](../battle.c) |
| ✅ | UpdateProgressGauge | 30 |  | [utilgen.c](../utilgen.c) |

</details>

## Depth 5 — Calls up to depth 4

### Unimplemented (17)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **DrawPlanetShipList** | 6 | W | `void DrawPlanetShipList(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawShipCargo** | 6 | W | `void DrawShipCargo(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ShowProgressGauge** | 15 |  | `void ShowProgressGauge(void)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **SetOrdersLbSel** | 30 | W | `void SetOrdersLbSel(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetBuildSelection** | 31 | W | `void SetBuildSelection(int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FTrackRaceDlg3** | 47 | W | `int16_t FTrackRaceDlg3(uint16_t, POINT, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **PszGetDestName** | 78 |  | `char * PszGetDestName(FLEET *32, uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **PopupVCRMenu** | 87 | W | `int16_t PopupVCRMenu(uint16_t, int16_t, int16_t, uint8_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **ScrollScanner** | 97 | W | `void ScrollScanner(int16_t, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **LComputePower** | 100 |  | `int32_t LComputePower(SHDEF *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **RemoteTerraforming** | 103 |  | `void RemoteTerraforming(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **RedrawScanSel** | 105 | W | `void RedrawScanSel(uint16_t, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **NewGameDlg3** | 108 | W | `int16_t NewGameDlg3(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **DrawFleetCargoXferSide** | 120 | W | `void DrawFleetCargoXferSide(uint16_t, RECT *, FLEET *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ReportColumnPopup** | 149 | W | `void ReportColumnPopup(POINT, int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FTrackRaceDlg2** | 154 | W | `int16_t FTrackRaceDlg2(uint16_t, POINT, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawScannerSBar** | 263 | W | `void DrawScannerSBar(uint16_t, RECT *, SBAR *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |

### Implemented (2)

<details><summary>Show 2 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | PszFormatString | 300 |  | [msg.c](../msg.c) |
| ✅ | SetVisPFPlanets | 404 |  | [save.c](../save.c) |

</details>

## Depth 6 — Calls up to depth 5

### Unimplemented (8)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **PszFormatMessage** | 14 |  | `char * PszFormatMessage(int16_t, int16_t *32)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **ComputeShdefPowers** | 30 |  | `void ComputeShdefPowers(void)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FillOrdersLB** | 41 | W | `void FillOrdersLB(void)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawXferDlg** | 46 | W | `void DrawXferDlg(uint16_t, uint16_t, RECT *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **CtrPointScan** | 75 | W | `void CtrPointScan(POINT, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **RaceWizardDlg3** | 102 | W | `int16_t RaceWizardDlg3(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **RaceWizardDlg2** | 179 | W | `int16_t RaceWizardDlg2(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawBuildSelHull** | 378 | W | `void DrawBuildSelHull(uint16_t, uint16_t, int16_t, RECT *)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |

### Implemented (2)

<details><summary>Show 2 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | PszFormatIds | 14 |  | [msg.c](../msg.c) |
| ✅ | SetVisiblePlanFleet | 28 |  | [save.c](../save.c) |

</details>

## Depth 7 — Calls up to depth 6

### Unimplemented (9)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **FAskKillTutor** | 23 | W | `int16_t FAskKillTutor(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **PszGetMessageN** | 23 |  | `char * PszGetMessageN(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **TutorError** | 26 | W | `void TutorError(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FEnsurePointOnScreen** | 50 | W | `int16_t FEnsurePointOnScreen(POINT, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **TutorDlg** | 75 | W | `int16_t TutorDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FDeleteBattlePlan** | 80 |  | `int16_t FDeleteBattlePlan(int16_t, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PasswordDlg** | 81 | W | `int16_t PasswordDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **MsgDlg** | 89 |  | `int16_t MsgDlg(uint16_t, uint16_t, uint16_t, int32_t)` |  | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **PrintMapDlg** | 150 | W | `int16_t PrintMapDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |

### Implemented (6)

<details><summary>Show 6 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | FileError | 19 |  | [file.c](../file.c) |
| ✅ | LphbAlloc | 56 |  | [memory.c](../memory.c) |
| ✅ | LphbReAlloc | 73 |  | [memory.c](../memory.c) |
| ✅ | RgToStream | 20 |  | [save.c](../save.c) |
| ✅ | TurnLog | 21 |  | [util.c](../util.c) |
| ✅ | WriteMemRt | 41 |  | [log.c](../log.c) |

</details>

## Depth 8 — Calls up to depth 7

### Unimplemented (7)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **FOKMergeDialog** | 25 | W | `int16_t FOKMergeDialog(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckCargo** | 45 | W | `int16_t FCheckCargo(FLEET *32, int16_t, int16_t, int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckFleetName** | 47 | W | `int16_t FCheckFleetName(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckBuilderPart** | 55 | W | `int16_t FCheckBuilderPart(int16_t, HS *, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckZip** | 58 | W | `int16_t FCheckZip(int16_t, ITEMACTION *32, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckQueue** | 68 | W | `int16_t FCheckQueue(int16_t, int16_t, uint16_t, uint16_t, uint16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckFleetWP** | 78 | W | `int16_t FCheckFleetWP(uint16_t, int16_t, uint16_t, int16_t, uint16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |

### Implemented (8)

<details><summary>Show 8 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | LogMakeValidXfer | 155 |  | [log.c](../log.c) |
| ✅ | LogMakeValidXferf | 43 |  | [log.c](../log.c) |
| ✅ | LogMergeFleet | 29 |  | [log.c](../log.c) |
| ✅ | LogSplitFleet | 20 |  | [log.c](../log.c) |
| ✅ | LpAlloc | 66 |  | [memory.c](../memory.c) |
| ✅ | RgFromStream | 24 |  | [file.c](../file.c) |
| ✅ | StreamOpen | 44 |  | [file.c](../file.c) |
| ✅ | WriteRt | 25 |  | [save.c](../save.c) |

</details>

## Depth 9 — Calls up to depth 8

### Unimplemented (9)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **FCheckLayingWP** | 43 | W | `int16_t FCheckLayingWP(uint16_t, int16_t, int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckColonizeWP** | 44 | W | `int16_t FCheckColonizeWP(uint16_t, int16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckPatrolWP** | 44 | W | `int16_t FCheckPatrolWP(uint16_t, int16_t, int16_t, uint16_t, uint16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FSetUpBatchProcessing** | 48 |  | `int16_t FSetUpBatchProcessing(void)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **WritePlayerMessages** | 56 |  | `void WritePlayerMessages(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **CopyFile** | 63 |  | `void CopyFile(char *, char *)` |  | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DumpUniverse** | 74 |  | `void DumpUniverse(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FCheckXferWP** | 90 | W | `int16_t FCheckXferWP(uint16_t, int16_t, int16_t, uint16_t, ITEMACTION *32)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FTutorialEnabledShipBuilder** | 234 | W | `int16_t FTutorialEnabledShipBuilder(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |

### Implemented (17)

<details><summary>Show 17 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | FCreateStuff | 269 | W | [init.c](../init.c) |
| ✅ | FWriteTutorialMFile | 90 |  | [log.c](../log.c) |
| ✅ | LogChangeFleet | 173 |  | [log.c](../log.c) |
| ✅ | LogChangePlanet | 134 |  | [log.c](../log.c) |
| ✅ | LogChangeThing | 51 |  | [log.c](../log.c) |
| ✅ | LpReAlloc | 47 |  | [memory.c](../memory.c) |
| ✅ | LpplAlloc | 21 |  | [memory.c](../memory.c) |
| ✅ | ReadIniSettings | 476 | W | [init.c](../init.c) |
| ✅ | ReadRt | 20 |  | [file.c](../file.c) |
| ✅ | WriteBOF | 36 |  | [save.c](../save.c) |
| ✅ | WriteBattlePlan | 41 |  | [save.c](../save.c) |
| ✅ | WriteBattles | 210 |  | [save.c](../save.c) |
| ✅ | WriteOrders | 32 |  | [save.c](../save.c) |
| ✅ | WritePlanet | 165 |  | [save.c](../save.c) |
| ✅ | WriteRtPlr | 58 |  | [save.c](../save.c) |
| ✅ | WriteRtShDef | 65 |  | [save.c](../save.c) |
| ✅ | WriteRtString | 31 |  | [save.c](../save.c) |

</details>

## Depth 10 — Calls up to depth 9

### Unimplemented (3)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **FWasRaceFile** | 109 |  | `int16_t FWasRaceFile(char *, int16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FFinishPlrMsgEntry** | 181 |  | `int16_t FFinishPlrMsgEntry(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FTutorTaskDone** | 2668 | W | `int16_t FTutorTaskDone(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |

### Implemented (11)

<details><summary>Show 11 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | FCreateFile | 30 |  | [save.c](../save.c) |
| ✅ | FLoadLogFile | 164 |  | [log.c](../log.c) |
| ✅ | FMarkFile | 174 |  | [save.c](../save.c) |
| ✅ | FOpenFile | 173 |  | [file.c](../file.c) |
| ✅ | FReadFleet | 200 |  | [file.c](../file.c) |
| ✅ | InitInstance | 45 | W | [init.c](../init.c) |
| ✅ | LpflNew | 95 |  | [util.c](../util.c) |
| ✅ | LpplReAlloc | 14 |  | [memory.c](../memory.c) |
| ✅ | LpthNew | 79 |  | [thing.c](../thing.c) |
| ✅ | ReadPlayerMessages | 90 |  | [msg.c](../msg.c) |
| ✅ | WriteFleet | 143 |  | [save.c](../save.c) |

</details>

## Depth 11 — Calls up to depth 10

### Unimplemented (5)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **LpflNewSplit** | 41 |  | `FLEET *32 LpflNewSplit(FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **AdvanceTutor** | 62 |  | `void AdvanceTutor(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FSaveRace** | 74 |  | `int16_t FSaveRace(char *, PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **MysteryTrader** | 99 |  | `void MysteryTrader(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DropSalvage** | 141 |  | `void DropSalvage(THING *32 *, int32_t *32, int16_t, POINT *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |

### Implemented (9)

<details><summary>Show 9 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CreateStartupShip | 72 |  | [create.c](../create.c) |
| ✅ | FAppendFile | 16 |  | [save.c](../save.c) |
| ✅ | FCheckFile | 65 |  | [file.c](../file.c) |
| ✅ | FCheckLogFile | 67 |  | [log.c](../log.c) |
| ✅ | FDupFleet | 53 |  | [util.c](../util.c) |
| ✅ | FDupPlanet | 55 |  | [util.c](../util.c) |
| ✅ | FNewTurnAvail | 30 |  | [file.c](../file.c) |
| ✅ | FWriteHistFile | 118 |  | [log.c](../log.c) |
| ✅ | FWriteLogFile | 79 |  | [log.c](../log.c) |

</details>

## Depth 12 — Calls up to depth 11

### Unimplemented (12)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **RandomEvents** | 14 |  | `void RandomEvents(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **PromptSaveGame** | 29 |  | `void PromptSaveGame(void)` | [file.c](../file.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **FDumpCargo** | 60 |  | `int16_t FDumpCargo(FLEET *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **CFindTurnsOutstanding** | 85 | W | `int16_t CFindTurnsOutstanding(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **MergeFleetsDlg** | 89 | W | `int16_t MergeFleetsDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **BattleVCR** | 101 | W | `void BattleVCR(int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **ScoreXDlg** | 124 | W | `int16_t ScoreXDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CreateSalvage** | 134 |  | `void CreateSalvage(FLEET *, THING *32 *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **RaceCreationWizard** | 163 | W | `int16_t RaceCreationWizard(uint16_t, int16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **IDropPart** | 211 | W | `int16_t IDropPart(POINT, HS, int16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **ZipOrderDlg** | 296 | W | `int16_t ZipOrderDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **ZipProdDlg** | 298 | W | `int16_t ZipProdDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |

### Implemented (8)

<details><summary>Show 8 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | BrowserDlg | 269 | W | [research.c](../research.c) |
| ✅ | FLookupFleet | 70 |  | [util.c](../util.c) |
| ✅ | FLookupPlanet | 91 |  | [util.c](../util.c) |
| ✅ | FLookupThing | 52 |  | [util.c](../util.c) |
| ✅ | LogChangeBtlplan | 15 |  | [log.c](../log.c) |
| ✅ | LogChangeName | 64 |  | [log.c](../log.c) |
| ✅ | LogChangeRelations | 22 |  | [log.c](../log.c) |
| ✅ | LogChangeShDef | 37 |  | [log.c](../log.c) |

</details>

## Depth 13 — Calls up to depth 12

### Unimplemented (8)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **CTurnsOutSafe** | 27 |  | `int16_t CTurnsOutSafe(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FEnumCalcJettison** | 65 |  | `int16_t FEnumCalcJettison(void *32, int16_t, int16_t, PLANET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **HtMineWindow** | 88 | W | `int16_t HtMineWindow(uint16_t, int16_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **RelationsDlg** | 119 | W | `int16_t RelationsDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **InitializeBoard** | 177 |  | `void InitializeBoard(FLEET *32, int16_t, uint16_t, uint8_t *, int16_t *, int16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **SimpleNewGameDlg** | 227 | W | `int16_t SimpleNewGameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **FleetTransferCargoBalance** | 337 |  | `void FleetTransferCargoBalance(FLEET *, FLEET *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **BattlePlansDlg** | 444 | W | `int16_t BattlePlansDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |

### Implemented (6)

<details><summary>Show 6 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CalcPlanetMaxPop | 53 |  | [planet.c](../planet.c) |
| ✅ | ChgCargo | 145 |  | [ship.c](../ship.c) |
| ✅ | DestroyCurGame | 130 |  | [file.c](../file.c) |
| ✅ | FLookupObject | 19 |  | [util.c](../util.c) |
| ✅ | FLookupSelPlanet | 28 |  | [util.c](../util.c) |
| ✅ | FLookupSelShip | 17 |  | [util.c](../util.c) |

</details>

## Depth 14 — Calls up to depth 13

### Unimplemented (10)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **PctPlanetCapacity** | 33 |  | `int16_t PctPlanetCapacity(PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **XferSupply** | 41 |  | `int32_t XferSupply(int16_t, int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FFleetSplitAll** | 53 |  | `int16_t FFleetSplitAll(FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **UpdateXferBtns** | 57 | W | `void UpdateXferBtns(void)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SaveGameState** | 69 | W | `void SaveGameState(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **KillShips** | 83 |  | `void KillShips(TOK *32, int16_t, int16_t, FLEET *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **BreedColonistsInTransit** | 98 |  | `void BreedColonistsInTransit(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **TransferToOthers** | 149 |  | `void TransferToOthers(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FStargateJump** | 233 |  | `int16_t FStargateJump(FLEET *32, int16_t, int16_t, int16_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FTravelThroughMineFields** | 535 |  | `int16_t FTravelThroughMineFields(FLEET *32, int16_t *, THING *32)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |

### Implemented (3)

<details><summary>Show 3 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CMaxFactories | 32 |  | [planet.c](../planet.c) |
| ✅ | CMaxMines | 32 |  | [planet.c](../planet.c) |
| ✅ | ChgPopFromPlanet | 176 |  | [util.c](../util.c) |

</details>

## Depth 15 — Calls up to depth 14

### Unimplemented (6)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **UpdatePopulations** | 73 |  | `void UpdatePopulations(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FSetupXferBtns** | 131 | W | `int16_t FSetupXferBtns(RECT *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FTrackXfer** | 147 | W | `int16_t FTrackXfer(uint16_t, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ThingDecay** | 166 |  | `void ThingDecay(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **PtDisplayPlanetPopInfo** | 247 | W | `POINT PtDisplayPlanetPopInfo(uint16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **InitProduction** | 331 |  | `void InitProduction(PROD *)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |

### Implemented (3)

<details><summary>Show 3 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CMaxOperableDefenses | 37 |  | [planet.c](../planet.c) |
| ✅ | CMaxOperableFactories | 45 |  | [planet.c](../planet.c) |
| ✅ | CMaxOperableMines | 45 |  | [planet.c](../planet.c) |

</details>

## Depth 16 — Calls up to depth 15

### Unimplemented (3)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **TransferDlg** | 122 | W | `int16_t TransferDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawPopup** | 266 | W | `void DrawPopup(uint16_t, uint16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **Popup** | 295 | W | `void Popup(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |

### Implemented (5)

<details><summary>Show 5 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CBuildProdItem | 381 |  | [turn2.c](../turn2.c) |
| ✅ | CFactoriesOperating | 42 |  | [planet.c](../planet.c) |
| ✅ | CMinesOperating | 44 |  | [planet.c](../planet.c) |
| ✅ | CResourcesAtPlanet | 85 |  | [planet.c](../planet.c) |
| ✅ | CalcPctSurvive | 56 |  | [util.c](../util.c) |

</details>

## Depth 17 — Calls up to depth 16

### Unimplemented (11)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **DrawPlanetMinSum** | 6 | W | `void DrawPlanetMinSum(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **PopupWndProc** | 47 | W | `int32_t PopupWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **UpdateGuesses** | 76 |  | `void UpdateGuesses(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **BrowserWndProc** | 141 | W | `int32_t BrowserWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **CalcPlayerScore** | 175 |  | `int32_t CalcPlayerScore(int16_t, SCORE *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawPlanetStats** | 254 | W | `void DrawPlanetStats(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FTrackSlot** | 311 | W | `int16_t FTrackSlot(uint16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **VCRDlg** | 335 | W | `int16_t VCRDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **DropColonists** | 410 |  | `void DropColonists(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DoBombing** | 494 |  | `void DoBombing(void)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **MoveThings** | 648 |  | `void MoveThings(int16_t)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |

## Depth 18 — Calls up to depth 17

### Unimplemented (2)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **FakeListProc** | 70 | W | `int32_t FakeListProc(uint16_t, uint16_t, uint16_t, int32_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **UpdatePlayerScores** | 258 |  | `void UpdatePlayerScores(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |

## Depth -1 — Cyclic Functions

### Unimplemented (92)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **DrawPlanetProduction** | 6 | W | `void DrawPlanetProduction(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FakeCEProc** | 18 | W | `int32_t FakeCEProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FakeComboProc** | 18 | W | `int32_t FakeComboProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **MineMinerals** | 21 |  | `void MineMinerals(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **SetScanWp** | 22 | W | `int16_t SetScanWp(int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DestroyAllIshdefSB** | 27 |  | `void DestroyAllIshdefSB(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ShipBuilder** | 32 | W | `int16_t ShipBuilder(POINT)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FinishProduction** | 40 | W | `void FinishProduction(int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FNearAWayPoint** | 41 | W | `int16_t FNearAWayPoint(POINT, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ProjectedResearchSpending** | 48 |  | `int32_t ProjectedResearchSpending(int32_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **FFindSomethingAndSelectIt** | 49 | W | `int16_t FFindSomethingAndSelectIt(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **Merge2Fleets** | 50 |  | `void Merge2Fleets(FLEET *32, FLEET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DoOrders** | 54 |  | `void DoOrders(int16_t)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **DoBattles** | 58 |  | `void DoBattles(int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **EnsureAis** | 60 |  | `void EnsureAis(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FindDlg** | 64 | W | `int16_t FindDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **KillQueuedMassPackets** | 66 |  | `void KillQueuedMassPackets(PLANET *32)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **InitializeProductionDlg** | 67 | W | `void InitializeProductionDlg(uint16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **ChangeProduction** | 68 | W | `int16_t ChangeProduction(int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FleetOrdersChangeTarget** | 68 |  | `void FleetOrdersChangeTarget(FLEET *32)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **KillQueuedShips** | 71 |  | `void KillQueuedShips(PLANET *32)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **PszProductionETA** | 71 |  | `char * PszProductionETA(PLANET *32, PLPROD *32, int16_t, int16_t *, int16_t *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **RemoveIshdefFromAllQueues** | 71 |  | `void RemoveIshdefFromAllQueues(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SelectAdjPlanet** | 73 | W | `void SelectAdjPlanet(int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **SelectOursAtObject** | 80 |  | `void SelectOursAtObject(POINT *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **PszGetETA** | 90 |  | `char * PszGetETA(uint16_t, FLEET *32, int16_t *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **DrawReport** | 91 | W | `void DrawReport(uint16_t, uint16_t, RECT *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **RestoreSelection** | 92 | W | `void RestoreSelection(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **DeleteCurWayPoint** | 93 |  | `void DeleteCurWayPoint(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FDeleteFleet** | 93 |  | `int16_t FDeleteFleet(int16_t, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **SelectAdjFleet** | 97 |  | `void SelectAdjFleet(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **VerifyTurns** | 108 |  | `void VerifyTurns(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **CchGetETA** | 109 | W | `int16_t CchGetETA(uint16_t, FLEET *32, char *, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FTrackResearchDlg** | 111 | W | `int16_t FTrackResearchDlg(uint16_t, int16_t, int16_t, int16_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **FCheckQueuedShip** | 112 | W | `int16_t FCheckQueuedShip(uint16_t, SHDEF *32, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FFleetMergeAll** | 119 |  | `int16_t FFleetMergeAll(FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FSelectSz** | 120 | W | `int16_t FSelectSz(char *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ChangeMainObjSel** | 127 | W | `void ChangeMainObjSel(int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ChangeScanSel** | 127 | W | `void ChangeScanSel(SCAN *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FCanFleetUseStargates** | 132 |  | `int16_t FCanFleetUseStargates(FLEET *32, POINT, POINT)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FillPlanetProdLB** | 133 | W | `void FillPlanetProdLB(uint16_t, PLPROD *32, PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **NewPasswordDlg** | 138 | W | `int16_t NewPasswordDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **MineWndProc** | 140 | W | `int32_t MineWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **PopupMineralScanChoices** | 143 | W | `void PopupMineralScanChoices(uint16_t, int16_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **InvertPaneBorder** | 144 | W | `POINT InvertPaneBorder(uint16_t, int16_t, POINT, POINT *)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **StartTutor** | 144 | W | `void StartTutor(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FAddWayPoint** | 151 | W | `int16_t FAddWayPoint(POINT, SCAN *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DestroyAllIshdef** | 153 |  | `void DestroyAllIshdef(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawProductionDlg** | 179 | W | `void DrawProductionDlg(uint16_t, uint16_t, RECT *, int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **IWarpBestForWaypoint** | 184 |  | `int16_t IWarpBestForWaypoint(FLEET *32, ORDER *32)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ClickInPlanetOrders** | 205 | W | `uint16_t ClickInPlanetOrders(POINT, int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ProductionDlg** | 213 | W | `int16_t ProductionDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **PlanetClick** | 219 | W | `void PlanetClick(int16_t, int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FFindNearestObject** | 228 |  | `int16_t FFindNearestObject(POINT, int16_t, SCAN *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FHandleMeasuringTape** | 247 | W | `int16_t FHandleMeasuringTape(SCAN *, POINT)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ExecuteReportClick** | 249 | W | `void ExecuteReportClick(POINT, int16_t, int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FHandleKey** | 254 | W | `int16_t FHandleKey(uint16_t, int16_t, int16_t, uint32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **TransferStuff** | 263 |  | `int16_t TransferStuff(int16_t, int16_t, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawShipOrders** | 264 | W | `void DrawShipOrders(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FDamageTok** | 294 |  | `int16_t FDamageTok(TOK *32, int16_t, int32_t *, int32_t, uint16_t, int16_t, int32_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DumpFleets** | 306 |  | `void DumpFleets(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ExecuteButton** | 309 | W | `void ExecuteButton(int16_t, int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **UpdateResearchStatus** | 318 |  | `void UpdateResearchStatus(int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **TbWndProc** | 322 | W | `int32_t TbWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **DumpPlanets** | 327 |  | `void DumpPlanets(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ReportDlg** | 330 |  | `int32_t ReportDlg(uint16_t, uint16_t, uint16_t, int32_t)` |  | [report.c](../decompiled/all/report.c) |
| ⬜ | **FDoCoolBattle** | 354 |  | `int16_t FDoCoolBattle(FLEET *32, int16_t, uint16_t *, uint16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **MineClick** | 375 | W | `void MineClick(int16_t, int16_t, int16_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **Produce** | 390 |  | `void Produce(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **NewGameWizard** | 414 | W | `void NewGameWizard(uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **ShipCommandProc** | 456 | W | `void ShipCommandProc(uint16_t, uint16_t, int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **NewGameDlg2** | 462 | W | `int16_t NewGameDlg2(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **ResearchDlg** | 481 | W | `int16_t ResearchDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **ScannerWndProc** | 494 | W | `int32_t ScannerWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DoThingInteractions** | 523 |  | `void DoThingInteractions(int16_t)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **FBuildObject** | 527 |  | `int16_t FBuildObject(PLANET *32, int16_t, int16_t, int16_t, int32_t *)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FHandleWayPointDrag** | 570 | W | `int16_t FHandleWayPointDrag(POINT)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ClickInShipOrders** | 606 | W | `uint16_t ClickInShipOrders(POINT, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **GenNewGameFromFile** | 634 |  | `int16_t GenNewGameFromFile(char *)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **PlanetWndProc** | 666 | W | `int32_t PlanetWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ProdCommandHandler** | 676 | W | `void ProdCommandHandler(uint16_t, uint16_t, int32_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FAttack** | 708 |  | `int16_t FAttack(int16_t, int16_t, BTLREC *32, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawReportItem** | 763 | W | `void DrawReportItem(uint16_t, RECT *, int16_t, int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ICompReport** | 800 | W | `int16_t ICompReport(void *, void *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **MessageWndProc** | 814 | W | `int32_t MessageWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FGenerateTurn** | 825 |  | `int16_t FGenerateTurn(void)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **MoveFleets** | 844 |  | `void MoveFleets(void)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **DrawShipWayPtOrders** | 891 | W | `void DrawShipWayPtOrders(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawMineSurvey** | 998 | W | `void DrawMineSurvey(uint16_t, RECT *)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **SlotDlg** | 1156 | W | `int16_t SlotDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **CommandHandler** | 1185 | W | `void CommandHandler(uint16_t, uint16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **SatisfyOrders** | 1687 |  | `void SatisfyOrders(int16_t)` | [turn3.c](../turn3.c) | [turn.c](../decompiled/all/turn.c) |

### Implemented (15)

<details><summary>Show 15 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | BringUpHostDlg | 174 | W | [mdi.c](../mdi.c) |
| ✅ | CreateTutorWorld | 74 |  | [create.c](../create.c) |
| ✅ | EstMineralsMined | 232 |  | [mine.c](../mine.c) |
| ✅ | EstimateItemProdSched | 207 |  | [produce.c](../produce.c) |
| ✅ | FLoadGame | 1221 |  | [file.c](../file.c) |
| ✅ | FOpenGame | 215 | W | [mdi.c](../mdi.c) |
| ✅ | FRunLogFile | 34 |  | [log.c](../log.c) |
| ✅ | FRunLogRecord | 821 |  | [log.c](../log.c) |
| ✅ | FWriteDataFile | 498 |  | [save.c](../save.c) |
| ✅ | FrameWndProc | 667 | W | [mdi.c](../mdi.c) |
| ✅ | GenerateWorld | 1700 |  | [create.c](../create.c) |
| ✅ | HostModeDialog | 305 | W | [mdi.c](../mdi.c) |
| ✅ | HostTimerProc | 177 | W | [mdi.c](../mdi.c) |
| ✅ | TitleWndProc | 336 | W | [mdi.c](../mdi.c) |
| ✅ | WinMain | 338 |  | [winmain.c](../winmain.c) |

</details>

