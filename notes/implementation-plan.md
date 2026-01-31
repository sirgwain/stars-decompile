# Implementation Plan

Auto-generated cross-reference of call graph depth and implementation status.

*AI functions excluded (103 functions from ai.c, ai2.c, ai3.c, ai4.c, aiu.c, aiutil.c)*

## Summary

| Depth | Label | Total | Implemented | Unimplemented |
|-------|-------|------:|------------:|--------------:|
| 0 | Depth 0 — Leaf Functions | 192 | 120 | 72 |
| 1 | Depth 1 — Calls Only Leaves | 73 | 31 | 42 |
| 2 | Depth 2 | 76 | 20 | 56 |
| 3 | Depth 3 | 59 | 9 | 50 |
| 4 | Depth 4 | 46 | 5 | 41 |
| 5 | Depth 5 | 19 | 1 | 18 |
| 6 | Depth 6 | 10 | 1 | 9 |
| 7 | Depth 7 | 15 | 3 | 12 |
| 8 | Depth 8 | 15 | 3 | 12 |
| 9 | Depth 9 | 26 | 5 | 21 |
| 10 | Depth 10 | 14 | 5 | 9 |
| 11 | Depth 11 | 14 | 2 | 12 |
| 12 | Depth 12 | 20 | 2 | 18 |
| 13 | Depth 13 | 14 | 3 | 11 |
| 14 | Depth 14 | 13 | 3 | 10 |
| 15 | Depth 15 | 9 | 3 | 6 |
| 16 | Depth 16 | 8 | 3 | 5 |
| 17 | Depth 17 | 11 | 0 | 11 |
| 18 | Depth 18 | 2 | 0 | 2 |
| -1 | Depth -1 — Cyclic Functions | 107 | 6 | 101 |
| | **Total** | **743** | **225** | **518** |

## Depth 0 — Leaf Functions

### Unimplemented (72)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **InitBtnTrack** | 29 | `void InitBtnTrack(BTNT *, uint16_t, uint16_t, RECT *, int16_t, int16_t, int16_t, int16_t, char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **IrcRaceDlgHitTest** | 30 | `int16_t IrcRaceDlgHitTest(POINT)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **MarkPlayersThatSentMsgs** | 30 | `void MarkPlayersThatSentMsgs(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FProdIsTerra** | 31 | `int16_t FProdIsTerra(PROD *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **IStargateFromLppl** | 31 | `int16_t IStargateFromLppl(PLANET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **CreateBackupDir** | 32 | `void CreateBackupDir(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FAttackPlayer** | 32 | `int16_t FAttackPlayer(FLEET *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **CreateShip** | 33 | `void CreateShip(int16_t, FLEET *32, int16_t, int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DxOfBtn** | 33 | `int16_t DxOfBtn(int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **WtFromLpfl** | 33 | `int32_t WtFromLpfl(FLEET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **HfontPrinterCreate** | 34 | `uint16_t HfontPrinterCreate(uint16_t, int16_t, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **HtMsgBox** | 34 | `int16_t HtMsgBox(POINT)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **ICompFleetPoint** | 34 | `int16_t ICompFleetPoint(void *, void *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawFuzzyBorder** | 35 | `void DrawFuzzyBorder(uint16_t, RECT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DrawSelectionArrow** | 35 | `void DrawSelectionArrow(uint16_t, RECT *, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **FCheckScanner** | 35 | `int16_t FCheckScanner(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckShipBuilder** | 35 | `int16_t FCheckShipBuilder(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **InitBattlePlan** | 35 | `void InitBattlePlan(BTLPLAN *32, int16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **FillFleetCompLB** | 36 | `void FillFleetCompLB(void)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **PszGetLine** | 36 | `char *32 PszGetLine(char *32 *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **NthValidShdef** | 37 | `SHDEF *32 NthValidShdef(int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **AskSaveDialog** | 38 | `int16_t AskSaveDialog(void)` | [file.c](../file.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **OrderInfoDlg** | 38 | `int16_t OrderInfoDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **DrawScanXorLines** | 41 | `void DrawScanXorLines(uint16_t, POINT *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FCheckSummary** | 41 | `int16_t FCheckSummary(uint16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **GetDxDyOrientation** | 42 | `void GetDxDyOrientation(int16_t, int16_t, POINT *, POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ScoreFromGiveAndTakeAndTactic** | 42 | `int32_t ScoreFromGiveAndTakeAndTactic(int32_t, int32_t, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FFleetCanJumpgate** | 43 | `int16_t FFleetCanJumpgate(FLEET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FGetMouseMove** | 43 | `int16_t FGetMouseMove(POINT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FGetRMouseMove** | 43 | `int16_t FGetRMouseMove(POINT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **InvalidateAdvPtsRect** | 43 | `void InvalidateAdvPtsRect(uint16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **IntToRoman** | 44 | `void IntToRoman(int16_t, char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **MarkFleet** | 44 | `void MarkFleet(FLEET *32, int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **IshFindSimilarDesign** | 45 | `int16_t IshFindSimilarDesign(HUL *32, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **LFetchScoreXVal** | 45 | `int32_t LFetchScoreXVal(SCOREX *32, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **InitTiles** | 46 | `void InitTiles(void)` | [init.c](../init.c) | [init.c](../decompiled/all/init.c) |
| ⬜ | **NthValidEnemyShdef** | 46 | `SHDEF *32 NthValidEnemyShdef(int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **PanicDlg** | 46 | `int16_t PanicDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCanMerge** | 47 | `int16_t FCanMerge(FLEET *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FIsTargetOfMdTarget** | 47 | `int16_t FIsTargetOfMdTarget(TOK *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **CommaFormatLong** | 48 | `int16_t CommaFormatLong(char *, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **Delay** | 48 | `void Delay(int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **PctTerraFromLpfl** | 48 | `int32_t PctTerraFromLpfl(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FQueueColonistDrop** | 49 | `int16_t FQueueColonistDrop(FLEET *32, PLANET *32, int32_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **CParseNumbers** | 51 | `int16_t CParseNumbers(char *32, int32_t *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **HcrsFromFrameWindowPt** | 53 | `uint16_t HcrsFromFrameWindowPt(POINT, int16_t *)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **MarkPlanet** | 53 | `void MarkPlanet(PLANET *32, int16_t, uint16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **FOtherStuffAtScanSel** | 54 | `int16_t FOtherStuffAtScanSel(void)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **NewPlanNameDlg** | 54 | `int16_t NewPlanNameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **GetVCVal** | 55 | `int16_t GetVCVal(GAME *, int16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **CshQueued** | 56 | `int16_t CshQueued(int16_t, int16_t *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **NoAutoTrackFleet** | 57 | `void NoAutoTrackFleet(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **BoundsCheckPlayer** | 58 | `void BoundsCheckPlayer(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **FCheckTemplate** | 59 | `int16_t FCheckTemplate(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **DrawDiamond** | 62 | `void DrawDiamond(uint16_t, RECT *, uint16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **FGetNextObjHere** | 62 | `int16_t FGetNextObjHere(SCAN *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FIsButtonDown** | 62 | `int16_t FIsButtonDown(int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FDestIsWP0** | 64 | `int16_t FDestIsWP0(FLEET *32)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CPlanetsInCircle** | 66 | `int16_t CPlanetsInCircle(POINT, int32_t)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **SetHScrollBar** | 66 | `void SetHScrollBar(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **IdmGiveTraderPart** | 68 | `int16_t IdmGiveTraderPart(uint16_t, int16_t, uint16_t *)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **DeleteWpFar** | 71 | `void DeleteWpFar(FLEET *32, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetFilteringGroups** | 73 | `void SetFilteringGroups(int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FLookupOrbitingXfer** | 76 | `int16_t FLookupOrbitingXfer(int16_t, int16_t, XFER *, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FDoesPrimaryTargetTypeExist** | 86 | `int16_t FDoesPrimaryTargetTypeExist(TOK *32, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **TerminateToolbarFocus** | 93 | `void TerminateToolbarFocus(int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **LinkFleets** | 105 | `void LinkFleets(int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DiaganolTextOut** | 133 | `void DiaganolTextOut(uint16_t, RECT *, char *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FIntersectCircleLine** | 137 | `int16_t FIntersectCircleLine(POINT, POINT, POINT, int32_t, int16_t, int16_t *, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **IValidateWormholePos** | 140 | `int16_t IValidateWormholePos(THING *32)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **DrawRadarCircle** | 165 | `void DrawRadarCircle(DRAWCIR *, RECT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **AnimateAttack** | 438 | `void AnimateAttack(uint16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |

### Implemented (120)

<details><summary>Show 120 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | AddBackTrailingSpaces | 15 | [utilgen.c](../utilgen.c) |
| ✅ | BoundPoints | 40 | [utilgen.c](../utilgen.c) |
| ✅ | BtlDataGet | 52 | [vcr.c](../vcr.c) |
| ✅ | CBattleKills | 45 | [vcr.c](../vcr.c) |
| ✅ | CBattles | 46 | [vcr.c](../vcr.c) |
| ✅ | CancelMemRt | 14 | [log.c](../log.c) |
| ✅ | CchTutorString | 58 | [tutor2.c](../tutor2.c) |
| ✅ | ChFromNybble | 35 | [utilgen.c](../utilgen.c) |
| ✅ | ChopLastWord | 21 | [utilgen.c](../utilgen.c) |
| ✅ | ChopTrailingSpaces | 15 | [utilgen.c](../utilgen.c) |
| ✅ | ClearFile | 25 | [util.c](../util.c) |
| ✅ | CtrTextOut | 20 | [utilgen.c](../utilgen.c) |
| ✅ | DGetDistance | 27 | [util.c](../util.c) |
| ✅ | DibNumColors | 36 | [utilgen.c](../utilgen.c) |
| ✅ | DpOfLpflIshdef | 28 | [util.c](../util.c) |
| ✅ | DrawHostOptions | 12 | [mdi.c](../mdi.c) |
| ✅ | DrawPlanetPrintDot | 22 | [util.c](../util.c) |
| ✅ | DxStreamTextOut | 23 | [utilgen.c](../utilgen.c) |
| ✅ | DxyFromSpdRound | 24 | [battle.c](../battle.c) |
| ✅ | DzFromBrcBrc | 22 | [battle.c](../battle.c) |
| ✅ | EnableVCRButtons | 28 | [vcr.c](../vcr.c) |
| ✅ | EnableZipBtns | 21 | [ship2.c](../ship2.c) |
| ✅ | EnableZipProdBtns | 25 | [produce.c](../produce.c) |
| ✅ | EnumLogRts | 27 | [log.c](../log.c) |
| ✅ | ExpandRc | 16 | [utilgen.c](../utilgen.c) |
| ✅ | FBadFileError | 21 | [file.c](../file.c) |
| ✅ | FBogusLong | 20 | [file.c](../file.c) |
| ✅ | FCanSplit | 21 | [ship.c](../ship.c) |
| ✅ | FCanSplitAll | 26 | [ship.c](../ship.c) |
| ✅ | FCheckBtlPlan | 25 | [tutor.c](../tutor.c) |
| ✅ | FCheckResearch | 20 | [tutor.c](../tutor.c) |
| ✅ | FColonizer | 29 | [ship2.c](../ship2.c) |
| ✅ | FFindPlayerMessage | 24 | [msg.c](../msg.c) |
| ✅ | FFuelTanker | 19 | [battle.c](../battle.c) |
| ✅ | FGetNMsgbig | 60 | [msg.c](../msg.c) |
| ✅ | FGetPrevLogRt | 29 | [log.c](../log.c) |
| ✅ | FHandleChar | 23 | [stars.c](../stars.c) |
| ✅ | FHullHasBombs | 32 | [battle.c](../battle.c) |
| ✅ | FHullHasTeeth | 28 | [battle.c](../battle.c) |
| ✅ | FRemovePlayerMessage | 28 | [msg.c](../msg.c) |
| ✅ | FScout | 29 | [ship2.c](../ship2.c) |
| ✅ | FShouldPartBeHidden | 73 | [research.c](../research.c) |
| ✅ | FStringFitsScreen | 31 | [utilgen.c](../utilgen.c) |
| ✅ | FakeEditProc | 19 | [ship.c](../ship.c) |
| ✅ | FreeHb | 31 | [memory.c](../memory.c) |
| ✅ | FreeHbr | 29 | [utilgen.c](../utilgen.c) |
| ✅ | FreeLpth | 16 | [thing.c](../thing.c) |
| ✅ | GetASubMenu | 46 | [mdi.c](../mdi.c) |
| ✅ | GetFileSeeds | 20 | [utilgen.c](../utilgen.c) |
| ✅ | GetMineFieldCounts | 31 | [mine.c](../mine.c) |
| ✅ | GetRaceGrbit | 24 | [race.c](../race.c) |
| ✅ | GetRaceStat | 12 | [race.c](../race.c) |
| ✅ | GetTrueHullCost | 18 | [util.c](../util.c) |
| ✅ | GetVCCheck | 12 | [create.c](../create.c) |
| ✅ | GetWindowRc | 23 | [mdi.c](../mdi.c) |
| ✅ | HandleFocusState | 20 | [planet.c](../planet.c) |
| ✅ | HbrGet | 46 | [utilgen.c](../utilgen.c) |
| ✅ | HideProgressGauge | 16 | [utilgen.c](../utilgen.c) |
| ✅ | HpalBlackReserved | 30 | [utilgen.c](../utilgen.c) |
| ✅ | ICompFleetPoint2 | 28 | [util.c](../util.c) |
| ✅ | ICompLong | 12 | [utilgen.c](../utilgen.c) |
| ✅ | IEmptyBmpFromGrhst | 23 | [build.c](../build.c) |
| ✅ | IRaceChecksum | 21 | [race.c](../race.c) |
| ✅ | IWarpMAFromLppl | 57 | [planet.c](../planet.c) |
| ✅ | IflFromLpfl | 24 | [util.c](../util.c) |
| ✅ | InitMDIApp | 178 | [mdi.c](../mdi.c) |
| ✅ | InitNewGame3 | 12 | [create.c](../create.c) |
| ✅ | IshdefPrimaryFromLpfl | 36 | [util.c](../util.c) |
| ✅ | LDistance2 | 19 | [utilgen.c](../utilgen.c) |
| ✅ | LGetNextFileXor | 47 | [utilgen.c](../utilgen.c) |
| ✅ | LSaltFromSz | 33 | [utilgen.c](../utilgen.c) |
| ✅ | LongFromSerialCh | 23 | [util.c](../util.c) |
| ✅ | LpengineFromId | 12 | [parts.c](../parts.c) |
| ✅ | LpflFromId | 42 | [util.c](../util.c) |
| ✅ | LphbFromLpHt | 31 | [memory.c](../memory.c) |
| ✅ | LphuldefSBFromId | 12 | [parts.c](../parts.c) |
| ✅ | LpplFromId | 44 | [util.c](../util.c) |
| ✅ | LpplanetaryFromId | 12 | [parts.c](../parts.c) |
| ✅ | LpplrComp | 12 | [create.c](../create.c) |
| ✅ | LpscannerFromId | 12 | [parts.c](../parts.c) |
| ✅ | LpshdefFromTok | 29 | [battle.c](../battle.c) |
| ✅ | LpshdefSBT | 12 | [parts.c](../parts.c) |
| ✅ | LpshdefT | 12 | [parts.c](../parts.c) |
| ✅ | LpthFromId | 24 | [util.c](../util.c) |
| ✅ | NybbleFromCh | 44 | [utilgen.c](../utilgen.c) |
| ✅ | OffsetRc | 16 | [utilgen.c](../utilgen.c) |
| ✅ | OutputFileString | 37 | [utilgen.c](../utilgen.c) |
| ✅ | PackageUpMsg | 62 | [msg.c](../msg.c) |
| ✅ | PctPlanetDesirability | 110 | [planet.c](../planet.c) |
| ✅ | PctWormholeMoves | 22 | [thing.c](../thing.c) |
| ✅ | PopRandom | 17 | [utilgen.c](../utilgen.c) |
| ✅ | PszCalcGravity | 26 | [planet.c](../planet.c) |
| ✅ | PszFromInt | 19 | [utilgen.c](../utilgen.c) |
| ✅ | PszFromLong | 19 | [utilgen.c](../utilgen.c) |
| ✅ | PszGetCompressedMessage | 56 | [msg.c](../msg.c) |
| ✅ | PszGetCompressedPlanet | 70 | [utilgen.c](../utilgen.c) |
| ✅ | PszGetCompressedString | 54 | [strings.c](../strings.c) |
| ✅ | PtToScan | 41 | [scan.c](../scan.c) |
| ✅ | PushRandom | 23 | [utilgen.c](../utilgen.c) |
| ✅ | Random | 69 | [utilgen.c](../utilgen.c) |
| ✅ | Randomize | 29 | [utilgen.c](../utilgen.c) |
| ✅ | Randomize2 | 31 | [utilgen.c](../utilgen.c) |
| ✅ | RcCtrTextOut | 37 | [utilgen.c](../utilgen.c) |
| ✅ | ReadBigBlock | 34 | [utilgen.c](../utilgen.c) |
| ✅ | ReadIniTileSettings | 86 | [init.c](../init.c) |
| ✅ | ResetHb | 26 | [memory.c](../memory.c) |
| ✅ | ResetMessages | 24 | [msg.c](../msg.c) |
| ✅ | ScanToPt | 41 | [scan.c](../scan.c) |
| ✅ | SetFileSeeds | 14 | [utilgen.c](../utilgen.c) |
| ✅ | SetRaceGrbit | 32 | [race.c](../race.c) |
| ✅ | SetRaceStat | 19 | [race.c](../race.c) |
| ✅ | SetSzWorkFromDt | 46 | [save.c](../save.c) |
| ✅ | SetVCCheck | 20 | [create.c](../create.c) |
| ✅ | ShowTutor | 23 | [tutor.c](../tutor.c) |
| ✅ | StickyDlgPos | 45 | [utilgen.c](../utilgen.c) |
| ✅ | StreamClose | 16 | [file.c](../file.c) |
| ✅ | TechStatus | 43 | [parts.c](../parts.c) |
| ✅ | UnmarkMineFields | 24 | [turn2.c](../turn2.c) |
| ✅ | UpdateBattleRecords | 65 | [file.c](../file.c) |
| ✅ | WPackLong | 27 | [util.c](../util.c) |

</details>

## Depth 1 — Calls Only Leaves

### Unimplemented (42)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **GetXferLeftRightRcs** | 18 | `void GetXferLeftRightRcs(RECT *, RECT *, RECT *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **LogicalToScan** | 18 | `void LogicalToScan(POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **WFromLpfl** | 22 | `uint16_t WFromLpfl(FLEET *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **ScanToLogical** | 24 | `void ScanToLogical(POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **SetVCVal** | 25 | `int16_t SetVCVal(GAME *, int16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **FSendPrependedPlrMsg** | 28 | `int16_t FSendPrependedPlrMsg(int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **MakeNewName** | 28 | `void MakeNewName(char *32)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FFleetHasTeeth** | 29 | `int16_t FFleetHasTeeth(FLEET *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **ItbFromPpt** | 29 | `int16_t ItbFromPpt(POINT *)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FCheckPlanetRoute** | 33 | `int16_t FCheckPlanetRoute(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **GetScanFleetOrientation** | 34 | `void GetScanFleetOrientation(FLEET *32, POINT *, POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DrawLockLight** | 36 | `void DrawLockLight(uint16_t, RECT *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **PszGetDistance** | 36 | `char * PszGetDistance(int16_t, int16_t, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FCanKillTok** | 44 | `int16_t FCanKillTok(TOK *32, TOK *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PszFromLongK** | 46 | `char * PszFromLongK(int32_t, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DecorateHullName** | 48 | `void DecorateHullName(int16_t, int16_t, char *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **GetTechLevelCost** | 48 | `int32_t GetTechLevelCost(int16_t, int16_t, int16_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **MarkPlanetsPlayerLost** | 50 | `void MarkPlanetsPlayerLost(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **ShowMainControls** | 50 | `void ShowMainControls(uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **HostOptionsDialog** | 54 | `int16_t HostOptionsDialog(uint16_t, uint16_t, uint16_t, int32_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FCheckSelection** | 55 | `int16_t FCheckSelection(uint16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **RandomSeedDlg** | 62 | `int16_t RandomSeedDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **RandomizeTokOrder** | 63 | `void RandomizeTokOrder(void)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **LDrawGauge** | 66 | `int32_t LDrawGauge(uint16_t, RECT *, int16_t, int32_t *, uint16_t *, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **InvalidateMineralBars** | 68 | `void InvalidateMineralBars(void)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **DrawABunchOfStars** | 70 | `void DrawABunchOfStars(uint16_t, RECT *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **IFindIdealWarp** | 70 | `int16_t IFindIdealWarp(FLEET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetVisPFFinish** | 71 | `void SetVisPFFinish(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **RenameZipDlg** | 73 | `int16_t RenameZipDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **WrapTextOut** | 74 | `void WrapTextOut(uint16_t, int16_t *, int16_t *, char *, int16_t, int16_t, int16_t, int16_t *, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **RenameDlg** | 77 | `int16_t RenameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FPacketDecay** | 78 | `int16_t FPacketDecay(THING *32, int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **CTorpHit** | 81 | `int32_t CTorpHit(int32_t, TOK *32, int16_t, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **InitScoreDlg** | 82 | `void InitScoreDlg(uint16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FValidSerialNo** | 93 | `int16_t FValidSerialNo(char *, int32_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **SortReportCache** | 97 | `void SortReportCache(int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **GetVCRStats** | 109 | `void GetVCRStats(int16_t, int32_t *, DV *, int32_t *, int16_t *)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **PtDisplayZipOrdInfo** | 129 | `POINT PtDisplayZipOrdInfo(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **GetShdefScannerRange** | 186 | `int16_t GetShdefScannerRange(SHDEF *32, int16_t, int16_t *, int16_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **LInnateRaceHabitability** | 252 | `int32_t LInnateRaceHabitability(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawBtn** | 260 | `void DrawBtn(uint16_t, RECT *, int16_t, int16_t, char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **_Draw3dFrame** | ? | `void _Draw3dFrame(uint16_t, RECT *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |

### Implemented (31)

<details><summary>Show 31 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | CMaxDefenses | 36 | [planet.c](../planet.c) |
| ✅ | CchGetString | 24 | [utilgen.c](../utilgen.c) |
| ✅ | FCheckPassword | 37 | [utilgen.c](../utilgen.c) |
| ✅ | FCompressUserString | 59 | [utilgen.c](../utilgen.c) |
| ✅ | FDecompressUserString | 67 | [utilgen.c](../utilgen.c) |
| ✅ | FGetSystemColors | 96 | [stars.c](../stars.c) |
| ✅ | FLookupPart | 354 | [parts.c](../parts.c) |
| ✅ | FSendPlrMsg | 28 | [msg.c](../msg.c) |
| ✅ | FValidSerialLong | 43 | [file.c](../file.c) |
| ✅ | FormatSerialAndEnv | 89 | [mdi.c](../mdi.c) |
| ✅ | FreeLp | 31 | [memory.c](../memory.c) |
| ✅ | GetFileStatus | 17 | [file.c](../file.c) |
| ✅ | GetTruePartCost | 119 | [ship.c](../ship.c) |
| ✅ | HdibLoadBigResource | 40 | [utilgen.c](../utilgen.c) |
| ✅ | HpalFromDib | 47 | [utilgen.c](../utilgen.c) |
| ✅ | IdmGetMessageN | 19 | [msg.c](../msg.c) |
| ✅ | InitializeMenu | 97 | [mdi.c](../mdi.c) |
| ✅ | LCalcFuelGainFromRamScoops | 79 | [util.c](../util.c) |
| ✅ | LdpFromItokDv | 49 | [vcr.c](../vcr.c) |
| ✅ | LphuldefFromId | 19 | [parts.c](../parts.c) |
| ✅ | PaletteSize | 22 | [utilgen.c](../utilgen.c) |
| ✅ | PctTrueMaxGrowth | 18 | [race.c](../race.c) |
| ✅ | PszCalcEnvVar | 27 | [planet.c](../planet.c) |
| ✅ | PszFleetNameFromWord | 39 | [util.c](../util.c) |
| ✅ | PszGetPlanetName | 26 | [util.c](../util.c) |
| ✅ | RefitFrameChildren | 131 | [mdi.c](../mdi.c) |
| ✅ | SetFileXorStream | 31 | [utilgen.c](../utilgen.c) |
| ✅ | SetScanScrollBars | 46 | [scan.c](../scan.c) |
| ✅ | SetWindowIniString | 54 | [mdi.c](../mdi.c) |
| ✅ | SzVersion | 22 | [util.c](../util.c) |
| ✅ | XorFileBuf | 40 | [utilgen.c](../utilgen.c) |

</details>

## Depth 2 — Calls up to depth 1

### Unimplemented (56)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **SetNGWTitle** | 19 | `void SetNGWTitle(uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **SetRCWTitle** | 19 | `void SetRCWTitle(uint16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **FillBattleDD** | 23 | `void FillBattleDD(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **PtDisplayString** | 23 | `POINT PtDisplayString(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **FIsPopupHullType** | 24 | `int16_t FIsPopupHullType(int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **IPlrAlsoCheater** | 29 | `int16_t IPlrAlsoCheater(int16_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **RightTextOut** | 34 | `void RightTextOut(uint16_t, int16_t, int16_t, char *, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DiscoverNewMinerals** | 36 | `void DiscoverNewMinerals(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FGetBestDefensePart** | 36 | `int16_t FGetBestDefensePart(PART *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FFleetHasBombs** | 37 | `int16_t FFleetHasBombs(FLEET *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FillZipProdLB** | 44 | `void FillZipProdLB(uint16_t, ZIPPRODQ *)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **StargateRangeFromLppl** | 48 | `int16_t StargateRangeFromLppl(PLANET *32, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FillBuildPartsLB** | 50 | `void FillBuildPartsLB(uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DrawMassWarpGauge** | 51 | `void DrawMassWarpGauge(uint16_t, RECT *, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **UpdateSlotGlobals** | 52 | `void UpdateSlotGlobals(void)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FCanBuildShdef** | 54 | `int16_t FCanBuildShdef(SHDEF *32, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FDrawTileNC** | 54 | `int16_t FDrawTileNC(uint16_t, TILE *, RECT *, char *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **GetFleetScannerRange** | 55 | `int16_t GetFleetScannerRange(FLEET *32, int16_t *, int16_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **IdFindAdjStarbase** | 55 | `int16_t IdFindAdjStarbase(int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CMineFromLpfl** | 59 | `int32_t CMineFromLpfl(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FTrackBtn** | 63 | `int16_t FTrackBtn(BTNT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **CostOfDevelopingItem** | 66 | `int32_t CostOfDevelopingItem(char *32)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **InitFromHuldef** | 67 | `int16_t InitFromHuldef(HUL *32, int16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FGetNewGameName** | 69 | `int16_t FGetNewGameName(char *)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **CPtsCloakFromLphs** | 71 | `int16_t CPtsCloakFromLphs(HS *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DpShieldOfShdef** | 71 | `int32_t DpShieldOfShdef(SHDEF *32, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawThingGauge** | 74 | `void DrawThingGauge(uint16_t, RECT *, THING *32, int16_t)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **DrawTutorText** | 74 | `void DrawTutorText(uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **PtDisplayResourceInfo** | 77 | `POINT PtDisplayResourceInfo(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **CMineSweepFromLphul** | 78 | `int32_t CMineSweepFromLphul(HUL *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **CShipsScanVis** | 78 | `int32_t CShipsScanVis(FLEET *32)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **PszNameProdItem** | 81 | `char * PszNameProdItem(PROD *32)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FMatchTarget** | 82 | `int16_t FMatchTarget(FLEET *32, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **PctJammerFromHul** | 84 | `int16_t PctJammerFromHul(HUL *32)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DrawPlanShip** | 93 | `void DrawPlanShip(uint16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CLayMinesFromLpfl** | 94 | `int32_t CLayMinesFromLpfl(FLEET *32, int16_t, int16_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **InvalidateReport** | 96 | `void InvalidateReport(int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **About** | 98 | `int16_t About(uint16_t, uint16_t, uint16_t, int32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **MarkTechsSeen** | 98 | `void MarkTechsSeen(HUL *32, int16_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **PtDisplayFactoryMineInfo** | 98 | `POINT PtDisplayFactoryMineInfo(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **UpdateShdefCost** | 100 | `void UpdateShdefCost(SHDEF *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DecorateMsgTitleBar** | 102 | `void DecorateMsgTitleBar(uint16_t, RECT *)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **MdCalcStargateDamage** | 118 | `int16_t MdCalcStargateDamage(int16_t, int16_t, int16_t, int16_t, int16_t *)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **HealShips** | 126 | `void HealShips(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **KillUsedWaypoints** | 127 | `void KillUsedWaypoints(void)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DxReportColHdr** | 140 | `int16_t DxReportColHdr(int16_t, int16_t, char *, uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **DpFromPtokBrcToBrc** | 166 | `int32_t DpFromPtokBrcToBrc(TOK *32, uint8_t, uint8_t, TOK *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PszGetTaskName** | 182 | `char * PszGetTaskName(FLEET *32, int16_t *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FCanTerraformLppl** | 185 | `int16_t FCanTerraformLppl(PLANET *32, int16_t *, int16_t *, int16_t *, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FCalcFleetBombDamage** | 189 | `int16_t FCalcFleetBombDamage(FLEET *32, int32_t *, int32_t *, int32_t *, int32_t *, int32_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **TooltipWndProc** | 210 | `int32_t TooltipWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **PtDisplayPlanetStateInfo** | 254 | `POINT PtDisplayPlanetStateInfo(uint16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **CplrBattle** | 271 | `int16_t CplrBattle(FLEET *32, uint16_t *, uint16_t *, uint16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **CAdvantagePoints** | 317 | `int16_t CAdvantagePoints(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawShipScanPath** | 339 | `void DrawShipScanPath(uint16_t, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **GetProductionCosts** | 386 | `void GetProductionCosts(PLANET *32, PROD *32, uint32_t *, int16_t, int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |

### Implemented (20)

<details><summary>Show 20 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | CBattleUnits | 73 | [vcr.c](../vcr.c) |
| ✅ | DibBlt | 36 | [utilgen.c](../utilgen.c) |
| ✅ | DibFromBitmap | 160 | [utilgen.c](../utilgen.c) |
| ✅ | FCreateFonts | 79 | [init.c](../init.c) |
| ✅ | FLookupPartX | 18 | [parts.c](../parts.c) |
| ✅ | FSendPlrMsg2 | 15 | [msg.c](../msg.c) |
| ✅ | FSerialAndEnvFromSz | 114 | [mdi.c](../mdi.c) |
| ✅ | FreePl | 13 | [memory.c](../memory.c) |
| ✅ | FreeStuff | 182 | [stars.c](../stars.c) |
| ✅ | GetDiskSerialNumber | 106 | [utilgen.c](../utilgen.c) |
| ✅ | GetIniWinRc | 73 | [init.c](../init.c) |
| ✅ | IMsgNext | 33 | [msg.c](../msg.c) |
| ✅ | IMsgPrev | 34 | [msg.c](../msg.c) |
| ✅ | InitNewGamePlr | 142 | [create.c](../create.c) |
| ✅ | LookupBestPlanetaryScanner | 27 | [parts.c](../parts.c) |
| ✅ | OutputSz | 31 | [util.c](../util.c) |
| ✅ | PszPlayerName | 74 | [util.c](../util.c) |
| ✅ | UnpackBattlePlan | 32 | [file.c](../file.c) |
| ✅ | WriteIniSettings | 304 | [mdi.c](../mdi.c) |
| ✅ | WtMaxShdefStat | 50 | [ship.c](../ship.c) |

</details>

## Depth 3 — Calls up to depth 2

### Unimplemented (50)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **DrawShipPlanet** | 8 | `void DrawShipPlanet(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **CheckInitiative** | 22 | `void CheckInitiative(TOK *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawMineralItem** | 30 | `void DrawMineralItem(uint16_t, int16_t, int16_t, int16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **IpctCanTerraformLppl** | 33 | `int16_t IpctCanTerraformLppl(PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CMineSweepFromLpfl** | 34 | `int32_t CMineSweepFromLpfl(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **RegenShield** | 37 | `void RegenShield(TOK *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **SetFleetDropDownSel** | 38 | `void SetFleetDropDownSel(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FCheckMessages** | 44 | `int16_t FCheckMessages(int16_t, int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **UninhabitPlanet** | 53 | `void UninhabitPlanet(PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **PctPlanetOptValue** | 54 | `int16_t PctPlanetOptValue(PLANET *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **TossNonAutoBuildItems** | 59 | `void TossNonAutoBuildItems(PLANET *32)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FillProdSrcLB** | 60 | `void FillProdSrcLB(uint16_t, int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **GetCachedFleetScannerRange** | 60 | `int16_t GetCachedFleetScannerRange(FLEET *32, int16_t *, int16_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawBitmapButton** | 61 | `void DrawBitmapButton(uint16_t, POINT, int16_t, int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **CheckTarget** | 63 | `void CheckTarget(TOK *32, FLEET *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **RestoreGameState** | 68 | `void RestoreGameState(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **AutoFleetOrder** | 71 | `void AutoFleetOrder(FLEET *32, PLANET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DrawDlgLBEntireItem** | 71 | `void DrawDlgLBEntireItem(DRAWITEMSTRUCT *32, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DrawProgressGauge** | 74 | `void DrawProgressGauge(uint16_t, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **AutoTerraform** | 76 | `void AutoTerraform(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **ReflowColumn** | 76 | `void ReflowColumn(int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **GetPlanetScannerRange** | 77 | `int16_t GetPlanetScannerRange(PLANET *32, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **ITechLearnATech** | 77 | `int16_t ITechLearnATech(int16_t, int16_t, int16_t, int16_t, uint16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PctCloakFromHuldef** | 79 | `int16_t PctCloakFromHuldef(HUL *32, int16_t, int16_t *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawRaceAdvantagePoints** | 81 | `void DrawRaceAdvantagePoints(uint16_t, RECT *, PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **IBestTerraform** | 81 | `int16_t IBestTerraform(PLANET *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawFleetBitmap** | 100 | `void DrawFleetBitmap(FLEET *32, uint16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawPlanetXferSide** | 104 | `void DrawPlanetXferSide(uint16_t, RECT *, PLANET *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawScanFleetCount** | 110 | `void DrawScanFleetCount(FLEET *32, int16_t, int16_t, uint16_t, uint16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DzMoveRangeToConsider** | 113 | `int16_t DzMoveRangeToConsider(TOK *32, uint16_t, uint8_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawHostDialog2** | 130 | `void DrawHostDialog2(uint16_t, uint16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **DrawNewGame3** | 132 | `void DrawNewGame3(uint16_t, uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **PctCloakFromLpfl** | 133 | `int16_t PctCloakFromLpfl(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DrawNewGame2** | 139 | `void DrawNewGame2(uint16_t, uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **SpankTheCheaters** | 156 | `void SpankTheCheaters(void)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawScoreReport** | 157 | `void DrawScoreReport(uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ScoreGuessBattleDamage** | 158 | `int32_t ScoreGuessBattleDamage(TOK *32, uint8_t, int16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FillBuildDD** | 167 | `void FillBuildDD(uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **ShowTooltip** | 181 | `void ShowTooltip(int16_t, RECT *)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **ValidateWaypoints** | 184 | `void ValidateWaypoints(void)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawProductionItem** | 186 | `void DrawProductionItem(uint16_t, RECT *, char *, int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **SetMsgTitle** | 193 | `void SetMsgTitle(uint16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **DrawVCReport** | 197 | `void DrawVCReport(uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CheckWeapons** | 206 | `void CheckWeapons(TOK *32, int16_t *, uint8_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawPlanetStarbase** | 209 | `void DrawPlanetStarbase(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawBuildSelComp** | 221 | `void DrawBuildSelComp(uint16_t, uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **NewGameDlg** | 225 | `int16_t NewGameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **DrawHistoryReport** | 276 | `void DrawHistoryReport(uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CreateRandomRace** | 338 | `void CreateRandomRace(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawResearchDlg** | 903 | `void DrawResearchDlg(uint16_t, uint16_t, RECT *, int16_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |

### Implemented (9)

<details><summary>Show 9 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | AlertSz | 30 | [utilgen.c](../utilgen.c) |
| ✅ | CreateChildWindows | 181 | [mdi.c](../mdi.c) |
| ✅ | EstFuelUse | 205 | [ship.c](../ship.c) |
| ✅ | FReadShDef | 142 | [file.c](../file.c) |
| ✅ | FSendPlrMsg2XGen | 57 | [msg.c](../msg.c) |
| ✅ | LGetFleetStat | 36 | [ship.c](../ship.c) |
| ✅ | PszGetFleetName | 65 | [util.c](../util.c) |
| ✅ | PszGetThingName | 65 | [util.c](../util.c) |
| ✅ | ReadRtPlr | 46 | [file.c](../file.c) |

</details>

## Depth 4 — Calls up to depth 3

### Unimplemented (41)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **DrawFleetComp** | 8 | `void DrawFleetComp(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **GetFuelFree** | 17 | `int32_t GetFuelFree(FLEET *32)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **GetCargoFree** | 27 | `int32_t GetCargoFree(FLEET *32)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetPlanetTitleBar** | 28 | `void SetPlanetTitleBar(uint16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **EndTutor** | 29 | `void EndTutor(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **UpdateProgressGauge** | 32 | `void UpdateProgressGauge(int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DrawToolbar** | 33 | `void DrawToolbar(uint16_t, RECT *)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **DrawCBEntireItem** | 44 | `void DrawCBEntireItem(DRAWITEMSTRUCT *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FTrackNewGameDlg3** | 49 | `int16_t FTrackNewGameDlg3(uint16_t, POINT, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **ProgressGaugeDlg** | 55 | `int16_t ProgressGaugeDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **PlanetaryClimateChange** | 62 | `void PlanetaryClimateChange(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **IBestRemoteTerra** | 65 | `int16_t IBestRemoteTerra(PLANET *32, int16_t, int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FillShipDD** | 66 | `void FillShipDD(int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **SetMineralTitleBar** | 73 | `void SetMineralTitleBar(uint16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **DrawThingXferSide** | 75 | `void DrawThingXferSide(uint16_t, RECT *, THING *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **EnsureTileSize** | 81 | `void EnsureTileSize(int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawFleetShipsXferSide** | 85 | `void DrawFleetShipsXferSide(uint16_t, RECT *, FLEET *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FuelFleets** | 94 | `void FuelFleets(void)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **DrawPlanShipBitmap** | 101 | `void DrawPlanShipBitmap(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawFleetGauge** | 111 | `void DrawFleetGauge(uint16_t, RECT *, FLEET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetVCRBoard** | 133 | `int16_t SetVCRBoard(int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **AutoRouteFleet** | 135 | `void AutoRouteFleet(FLEET *32, PLANET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **RaceWizardDlg6** | 136 | `int16_t RaceWizardDlg6(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawRace3** | 139 | `void DrawRace3(uint16_t, uint16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **RaceWizardDlg4** | 147 | `int16_t RaceWizardDlg4(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **UpdateOrdersDDs** | 152 | `void UpdateOrdersDDs(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **RaceWizardDlg5** | 157 | `int16_t RaceWizardDlg5(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **MeteorStrike** | 159 | `void MeteorStrike(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **PopupMenu** | 184 | `int16_t PopupMenu(uint16_t, int16_t, int16_t, int16_t, int32_t *, char * *, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **SetVisPFInit** | 199 | `void SetVisPFInit(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **DrawRace2** | 227 | `void DrawRace2(uint16_t, uint16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **SetVisPFThings** | 231 | `void SetVisPFThings(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **SweepForMines** | 233 | `void SweepForMines(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DrawSlotDlg** | 261 | `void DrawSlotDlg(uint16_t, uint16_t, RECT *, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DxyMoveTokTo** | 265 | `int16_t DxyMoveTokTo(TOK *32, int16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **SetVisPFFleets** | 321 | `void SetVisPFFleets(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **RaceWizardDlg1** | 338 | `int16_t RaceWizardDlg1(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **SendBattleMessages** | 426 | `void SendBattleMessages(FLEET *32, int16_t, int16_t, uint16_t *, int16_t, int16_t, int16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawVCR** | 538 | `void DrawVCR(uint16_t, int16_t, int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **DrawScanner** | 1200 | `int16_t DrawScanner(uint16_t, RECT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DisplayComponentInfo** | 1329 | `void DisplayComponentInfo(uint16_t, int16_t, int16_t, PART *)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |

### Implemented (5)

<details><summary>Show 5 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | DirtyGame | 15 | [log.c](../log.c) |
| ✅ | FReadPlanet | 209 | [file.c](../file.c) |
| ✅ | LFuelUseToWaypoint | 118 | [ship.c](../ship.c) |
| ✅ | PszGetLocName | 35 | [util.c](../util.c) |
| ✅ | SpdOfShip | 139 | [battle.c](../battle.c) |

</details>

## Depth 5 — Calls up to depth 4

### Unimplemented (18)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **DrawPlanetShipList** | 8 | `void DrawPlanetShipList(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawShipCargo** | 8 | `void DrawShipCargo(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ShowProgressGauge** | 17 | `void ShowProgressGauge(void)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **SetOrdersLbSel** | 30 | `void SetOrdersLbSel(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetBuildSelection** | 33 | `void SetBuildSelection(int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FTrackRaceDlg3** | 49 | `int16_t FTrackRaceDlg3(uint16_t, POINT, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **PszGetDestName** | 82 | `char * PszGetDestName(FLEET *32, uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **PopupVCRMenu** | 89 | `int16_t PopupVCRMenu(uint16_t, int16_t, int16_t, uint8_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **ScrollScanner** | 99 | `void ScrollScanner(int16_t, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **LComputePower** | 102 | `int32_t LComputePower(SHDEF *32)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **RemoteTerraforming** | 105 | `void RemoteTerraforming(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **RedrawScanSel** | 107 | `void RedrawScanSel(uint16_t, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **NewGameDlg3** | 110 | `int16_t NewGameDlg3(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **DrawFleetCargoXferSide** | 122 | `void DrawFleetCargoXferSide(uint16_t, RECT *, FLEET *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ReportColumnPopup** | 151 | `void ReportColumnPopup(POINT, int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FTrackRaceDlg2** | 156 | `int16_t FTrackRaceDlg2(uint16_t, POINT, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawScannerSBar** | 265 | `void DrawScannerSBar(uint16_t, RECT *, SBAR *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **SetVisPFPlanets** | 406 | `void SetVisPFPlanets(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |

### Implemented (1)

<details><summary>Show 1 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | PszFormatString | 302 | [msg.c](../msg.c) |

</details>

## Depth 6 — Calls up to depth 5

### Unimplemented (9)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **PszFormatMessage** | 16 | `char * PszFormatMessage(int16_t, int16_t *32)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **SetVisiblePlanFleet** | 30 | `void SetVisiblePlanFleet(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **ComputeShdefPowers** | 32 | `void ComputeShdefPowers(void)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FillOrdersLB** | 41 | `void FillOrdersLB(void)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawXferDlg** | 48 | `void DrawXferDlg(uint16_t, uint16_t, RECT *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **CtrPointScan** | 77 | `void CtrPointScan(POINT, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **RaceWizardDlg3** | 104 | `int16_t RaceWizardDlg3(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **RaceWizardDlg2** | 181 | `int16_t RaceWizardDlg2(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawBuildSelHull** | 380 | `void DrawBuildSelHull(uint16_t, uint16_t, int16_t, RECT *)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |

### Implemented (1)

<details><summary>Show 1 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | PszFormatIds | 16 | [msg.c](../msg.c) |

</details>

## Depth 7 — Calls up to depth 6

### Unimplemented (12)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **TurnLog** | 21 | `void TurnLog(int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **RgToStream** | 22 | `void RgToStream(void *32, uint16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **FAskKillTutor** | 25 | `int16_t FAskKillTutor(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **PszGetMessageN** | 25 | `char * PszGetMessageN(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **TutorError** | 28 | `void TutorError(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **WriteMemRt** | 43 | `void WriteMemRt(int16_t, int16_t, void *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FEnsurePointOnScreen** | 52 | `int16_t FEnsurePointOnScreen(POINT, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **TutorDlg** | 77 | `int16_t TutorDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FDeleteBattlePlan** | 82 | `int16_t FDeleteBattlePlan(int16_t, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PasswordDlg** | 84 | `int16_t PasswordDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **MsgDlg** | 92 | `int16_t MsgDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **PrintMapDlg** | 150 | `int16_t PrintMapDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |

### Implemented (3)

<details><summary>Show 3 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | FileError | 21 | [file.c](../file.c) |
| ✅ | LphbAlloc | 58 | [memory.c](../memory.c) |
| ✅ | LphbReAlloc | 75 | [memory.c](../memory.c) |

</details>

## Depth 8 — Calls up to depth 7

### Unimplemented (12)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **LogSplitFleet** | 22 | `void LogSplitFleet(int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FOKMergeDialog** | 25 | `int16_t FOKMergeDialog(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **WriteRt** | 25 | `void WriteRt(int16_t, int16_t, void *32)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **LogMergeFleet** | 31 | `void LogMergeFleet(int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **LogMakeValidXferf** | 45 | `void LogMakeValidXferf(LOGXFERF *, LOGXFERF *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FCheckCargo** | 47 | `int16_t FCheckCargo(FLEET *32, int16_t, int16_t, int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckFleetName** | 49 | `int16_t FCheckFleetName(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckBuilderPart** | 57 | `int16_t FCheckBuilderPart(int16_t, HS *, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckZip** | 60 | `int16_t FCheckZip(int16_t, ITEMACTION *32, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckQueue** | 70 | `int16_t FCheckQueue(int16_t, int16_t, uint16_t, uint16_t, uint16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckFleetWP** | 80 | `int16_t FCheckFleetWP(uint16_t, int16_t, uint16_t, int16_t, uint16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **LogMakeValidXfer** | 156 | `void LogMakeValidXfer(LOGXFER *, LOGXFER *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |

### Implemented (3)

<details><summary>Show 3 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | LpAlloc | 68 | [memory.c](../memory.c) |
| ✅ | RgFromStream | 26 | [file.c](../file.c) |
| ✅ | StreamOpen | 46 | [file.c](../file.c) |

</details>

## Depth 9 — Calls up to depth 8

### Unimplemented (21)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **WriteRtString** | 31 | `void WriteRtString(char *32)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **WriteOrders** | 32 | `void WriteOrders(FLEET *32)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **WriteBOF** | 36 | `void WriteBOF(int16_t, int16_t, int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **WriteBattlePlan** | 41 | `void WriteBattlePlan(BTLPLAN *32, int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **FCheckLayingWP** | 45 | `int16_t FCheckLayingWP(uint16_t, int16_t, int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckColonizeWP** | 46 | `int16_t FCheckColonizeWP(uint16_t, int16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckPatrolWP** | 46 | `int16_t FCheckPatrolWP(uint16_t, int16_t, int16_t, uint16_t, uint16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FSetUpBatchProcessing** | 50 | `int16_t FSetUpBatchProcessing(void)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **LogChangeThing** | 53 | `void LogChangeThing(THING *32, THING *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **WritePlayerMessages** | 56 | `void WritePlayerMessages(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **WriteRtPlr** | 58 | `void WriteRtPlr(PLAYER *, uint8_t *)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **CopyFile** | 65 | `void CopyFile(char *, char *)` |  | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **WriteRtShDef** | 65 | `void WriteRtShDef(SHDEF *32, uint8_t * *)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **DumpUniverse** | 76 | `void DumpUniverse(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FCheckXferWP** | 92 | `int16_t FCheckXferWP(uint16_t, int16_t, int16_t, uint16_t, ITEMACTION *32)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FWriteTutorialMFile** | 92 | `int16_t FWriteTutorialMFile(int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **LogChangePlanet** | 136 | `void LogChangePlanet(PLANET *32, PLANET *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **WritePlanet** | 166 | `void WritePlanet(PLANET *32, int16_t, int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **LogChangeFleet** | 175 | `void LogChangeFleet(FLEET *32, FLEET *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **WriteBattles** | 210 | `void WriteBattles(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **FTutorialEnabledShipBuilder** | 236 | `int16_t FTutorialEnabledShipBuilder(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |

### Implemented (5)

<details><summary>Show 5 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | FCreateStuff | 271 | [init.c](../init.c) |
| ✅ | LpReAlloc | 49 | [memory.c](../memory.c) |
| ✅ | LpplAlloc | 23 | [memory.c](../memory.c) |
| ✅ | ReadIniSettings | 478 | [init.c](../init.c) |
| ✅ | ReadRt | 22 | [file.c](../file.c) |

</details>

## Depth 10 — Calls up to depth 9

### Unimplemented (9)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **FCreateFile** | 32 | `int16_t FCreateFile(uint16_t, int16_t, char *)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **LpthNew** | 81 | `THING *32 LpthNew(int16_t, int16_t)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **LpflNew** | 97 | `FLEET *32 LpflNew(int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FWasRaceFile** | 111 | `int16_t FWasRaceFile(char *, int16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **WriteFleet** | 143 | `void WriteFleet(FLEET *32)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **FLoadLogFile** | 166 | `int16_t FLoadLogFile(char *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FMarkFile** | 175 | `int16_t FMarkFile(uint16_t, int16_t, int16_t, int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **FFinishPlrMsgEntry** | 181 | `int16_t FFinishPlrMsgEntry(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FTutorTaskDone** | 2668 | `int16_t FTutorTaskDone(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |

### Implemented (5)

<details><summary>Show 5 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | FOpenFile | 175 | [file.c](../file.c) |
| ✅ | FReadFleet | 202 | [file.c](../file.c) |
| ✅ | InitInstance | 47 | [init.c](../init.c) |
| ✅ | LpplReAlloc | 16 | [memory.c](../memory.c) |
| ✅ | ReadPlayerMessages | 92 | [msg.c](../msg.c) |

</details>

## Depth 11 — Calls up to depth 10

### Unimplemented (12)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **FAppendFile** | 18 | `int16_t FAppendFile(int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **LpflNewSplit** | 43 | `FLEET *32 LpflNewSplit(FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FDupFleet** | 55 | `int16_t FDupFleet(FLEET *32, FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FDupPlanet** | 57 | `int16_t FDupPlanet(PLANET *32, PLANET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **AdvanceTutor** | 64 | `void AdvanceTutor(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckLogFile** | 69 | `int16_t FCheckLogFile(int16_t, int16_t *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CreateStartupShip** | 74 | `int16_t CreateStartupShip(int16_t, int16_t, int16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **FSaveRace** | 75 | `int16_t FSaveRace(char *, PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **FWriteLogFile** | 79 | `int16_t FWriteLogFile(char *, int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **MysteryTrader** | 101 | `void MysteryTrader(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FWriteHistFile** | 117 | `int16_t FWriteHistFile(int16_t)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DropSalvage** | 143 | `void DropSalvage(THING *32 *, int32_t *32, int16_t, POINT *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |

### Implemented (2)

<details><summary>Show 2 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | FCheckFile | 67 | [file.c](../file.c) |
| ✅ | FNewTurnAvail | 32 | [file.c](../file.c) |

</details>

## Depth 12 — Calls up to depth 11

### Unimplemented (18)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **RandomEvents** | 16 | `void RandomEvents(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **LogChangeBtlplan** | 17 | `void LogChangeBtlplan(BTLPLAN *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **LogChangeRelations** | 24 | `void LogChangeRelations(void)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **PromptSaveGame** | 31 | `void PromptSaveGame(void)` | [file.c](../file.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **LogChangeShDef** | 39 | `void LogChangeShDef(SHDEF *32)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FLookupThing** | 54 | `int16_t FLookupThing(int16_t, THING *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FDumpCargo** | 62 | `int16_t FDumpCargo(FLEET *32)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **LogChangeName** | 66 | `void LogChangeName(int16_t, int16_t, char *)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FLookupFleet** | 72 | `int16_t FLookupFleet(int16_t, FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **CFindTurnsOutstanding** | 87 | `int16_t CFindTurnsOutstanding(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **MergeFleetsDlg** | 91 | `int16_t MergeFleetsDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **BattleVCR** | 103 | `void BattleVCR(int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **ScoreXDlg** | 127 | `int16_t ScoreXDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CreateSalvage** | 136 | `void CreateSalvage(FLEET *, THING *32 *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **RaceCreationWizard** | 165 | `int16_t RaceCreationWizard(uint16_t, int16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **IDropPart** | 219 | `int16_t IDropPart(POINT, HS, int16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **ZipOrderDlg** | 299 | `int16_t ZipOrderDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **ZipProdDlg** | 301 | `int16_t ZipProdDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |

### Implemented (2)

<details><summary>Show 2 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | BrowserDlg | 270 | [research.c](../research.c) |
| ✅ | FLookupPlanet | 93 | [util.c](../util.c) |

</details>

## Depth 13 — Calls up to depth 12

### Unimplemented (11)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **FLookupSelShip** | 19 | `int16_t FLookupSelShip(FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FLookupObject** | 21 | `int16_t FLookupObject(int16_t, int16_t, void *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **CTurnsOutSafe** | 29 | `int16_t CTurnsOutSafe(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FEnumCalcJettison** | 65 | `int16_t FEnumCalcJettison(void *32, int16_t, int16_t, PLANET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **HtMineWindow** | 90 | `int16_t HtMineWindow(uint16_t, int16_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **RelationsDlg** | 121 | `int16_t RelationsDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **ChgCargo** | 147 | `int32_t ChgCargo(int16_t, int16_t, int16_t, int32_t, void *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **InitializeBoard** | 179 | `void InitializeBoard(FLEET *32, int16_t, uint16_t, uint8_t *, int16_t *, int16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **SimpleNewGameDlg** | 229 | `int16_t SimpleNewGameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **FleetTransferCargoBalance** | 339 | `void FleetTransferCargoBalance(FLEET *, FLEET *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **BattlePlansDlg** | 446 | `int16_t BattlePlansDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |

### Implemented (3)

<details><summary>Show 3 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | CalcPlanetMaxPop | 55 | [planet.c](../planet.c) |
| ✅ | DestroyCurGame | 132 | [file.c](../file.c) |
| ✅ | FLookupSelPlanet | 30 | [util.c](../util.c) |

</details>

## Depth 14 — Calls up to depth 13

### Unimplemented (10)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **PctPlanetCapacity** | 35 | `int16_t PctPlanetCapacity(PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **XferSupply** | 43 | `int32_t XferSupply(int16_t, int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FFleetSplitAll** | 55 | `int16_t FFleetSplitAll(FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **UpdateXferBtns** | 59 | `void UpdateXferBtns(void)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SaveGameState** | 71 | `void SaveGameState(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **KillShips** | 85 | `void KillShips(TOK *32, int16_t, int16_t, FLEET *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **BreedColonistsInTransit** | 100 | `void BreedColonistsInTransit(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **TransferToOthers** | 151 | `void TransferToOthers(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FStargateJump** | 235 | `int16_t FStargateJump(FLEET *32, int16_t, int16_t, int16_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **FTravelThroughMineFields** | 537 | `int16_t FTravelThroughMineFields(FLEET *32, int16_t *, THING *32)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |

### Implemented (3)

<details><summary>Show 3 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | CMaxFactories | 34 | [planet.c](../planet.c) |
| ✅ | CMaxMines | 34 | [planet.c](../planet.c) |
| ✅ | ChgPopFromPlanet | 178 | [util.c](../util.c) |

</details>

## Depth 15 — Calls up to depth 14

### Unimplemented (6)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **UpdatePopulations** | 75 | `void UpdatePopulations(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FSetupXferBtns** | 133 | `int16_t FSetupXferBtns(RECT *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FTrackXfer** | 149 | `int16_t FTrackXfer(uint16_t, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ThingDecay** | 168 | `void ThingDecay(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **PtDisplayPlanetPopInfo** | 249 | `POINT PtDisplayPlanetPopInfo(uint16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **InitProduction** | 333 | `void InitProduction(PROD *)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |

### Implemented (3)

<details><summary>Show 3 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | CMaxOperableDefenses | 39 | [planet.c](../planet.c) |
| ✅ | CMaxOperableFactories | 47 | [planet.c](../planet.c) |
| ✅ | CMaxOperableMines | 47 | [planet.c](../planet.c) |

</details>

## Depth 16 — Calls up to depth 15

### Unimplemented (5)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **CFactoriesOperating** | 44 | `int16_t CFactoriesOperating(PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **TransferDlg** | 126 | `int16_t TransferDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawPopup** | 268 | `void DrawPopup(uint16_t, uint16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **Popup** | 296 | `void Popup(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **CBuildProdItem** | 383 | `int16_t CBuildProdItem(PLANET *32, PROD *32, PROD *, int32_t *, int16_t, int16_t *, int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |

### Implemented (3)

<details><summary>Show 3 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | CMinesOperating | 46 | [planet.c](../planet.c) |
| ✅ | CResourcesAtPlanet | 87 | [planet.c](../planet.c) |
| ✅ | CalcPctSurvive | 58 | [util.c](../util.c) |

</details>

## Depth 17 — Calls up to depth 16

### Unimplemented (11)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **DrawPlanetMinSum** | 8 | `void DrawPlanetMinSum(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **PopupWndProc** | 49 | `int32_t PopupWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **UpdateGuesses** | 78 | `void UpdateGuesses(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **BrowserWndProc** | 143 | `int32_t BrowserWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **CalcPlayerScore** | 177 | `int32_t CalcPlayerScore(int16_t, SCORE *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawPlanetStats** | 256 | `void DrawPlanetStats(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FTrackSlot** | 311 | `int16_t FTrackSlot(uint16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **VCRDlg** | 339 | `int16_t VCRDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **DropColonists** | 412 | `void DropColonists(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DoBombing** | 494 | `void DoBombing(void)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **MoveThings** | 650 | `void MoveThings(int16_t)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |

## Depth 18 — Calls up to depth 17

### Unimplemented (2)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **FakeListProc** | 70 | `int32_t FakeListProc(uint16_t, uint16_t, uint16_t, int32_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **UpdatePlayerScores** | 260 | `void UpdatePlayerScores(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |

## Depth -1 — Cyclic Functions

### Unimplemented (101)

| | Function | Lines | Prototype | Source | Decompiled |
|---|----------|------:|-----------|--------|------------|
| ⬜ | **DrawPlanetProduction** | 8 | `void DrawPlanetProduction(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FakeCEProc** | 18 | `int32_t FakeCEProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FakeComboProc** | 20 | `int32_t FakeComboProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **MineMinerals** | 23 | `void MineMinerals(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **SetScanWp** | 24 | `int16_t SetScanWp(int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DestroyAllIshdefSB** | 29 | `void DestroyAllIshdefSB(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FRunLogFile** | 34 | `int16_t FRunLogFile(void)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ShipBuilder** | 34 | `int16_t ShipBuilder(POINT)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FinishProduction** | 42 | `void FinishProduction(int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FNearAWayPoint** | 43 | `int16_t FNearAWayPoint(POINT, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ProjectedResearchSpending** | 50 | `int32_t ProjectedResearchSpending(int32_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **FFindSomethingAndSelectIt** | 51 | `int16_t FFindSomethingAndSelectIt(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **Merge2Fleets** | 52 | `void Merge2Fleets(FLEET *32, FLEET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DoOrders** | 56 | `void DoOrders(int16_t)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **DoBattles** | 60 | `void DoBattles(int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **EnsureAis** | 62 | `void EnsureAis(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FindDlg** | 67 | `int16_t FindDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **InitializeProductionDlg** | 68 | `void InitializeProductionDlg(uint16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **KillQueuedMassPackets** | 68 | `void KillQueuedMassPackets(PLANET *32)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **ChangeProduction** | 70 | `int16_t ChangeProduction(int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FleetOrdersChangeTarget** | 70 | `void FleetOrdersChangeTarget(FLEET *32)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **KillQueuedShips** | 71 | `void KillQueuedShips(PLANET *32)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **PszProductionETA** | 73 | `char * PszProductionETA(PLANET *32, PLPROD *32, int16_t, int16_t *, int16_t *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **RemoveIshdefFromAllQueues** | 73 | `void RemoveIshdefFromAllQueues(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SelectAdjPlanet** | 75 | `void SelectAdjPlanet(int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **CreateTutorWorld** | 76 | `void CreateTutorWorld(void)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **SelectOursAtObject** | 80 | `void SelectOursAtObject(POINT *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawReport** | 93 | `void DrawReport(uint16_t, uint16_t, RECT *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **PszGetETA** | 94 | `char * PszGetETA(uint16_t, FLEET *32, int16_t *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **RestoreSelection** | 94 | `void RestoreSelection(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **DeleteCurWayPoint** | 95 | `void DeleteCurWayPoint(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FDeleteFleet** | 95 | `int16_t FDeleteFleet(int16_t, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **SelectAdjFleet** | 99 | `void SelectAdjFleet(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **VerifyTurns** | 110 | `void VerifyTurns(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **CchGetETA** | 111 | `int16_t CchGetETA(uint16_t, FLEET *32, char *, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FTrackResearchDlg** | 113 | `int16_t FTrackResearchDlg(uint16_t, int16_t, int16_t, int16_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **FCheckQueuedShip** | 114 | `int16_t FCheckQueuedShip(uint16_t, SHDEF *32, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FSelectSz** | 120 | `int16_t FSelectSz(char *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FFleetMergeAll** | 121 | `int16_t FFleetMergeAll(FLEET *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **ChangeMainObjSel** | 127 | `void ChangeMainObjSel(int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ChangeScanSel** | 129 | `void ChangeScanSel(SCAN *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FCanFleetUseStargates** | 134 | `int16_t FCanFleetUseStargates(FLEET *32, POINT, POINT)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FillPlanetProdLB** | 134 | `void FillPlanetProdLB(uint16_t, PLPROD *32, PLANET *32)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **NewPasswordDlg** | 141 | `int16_t NewPasswordDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **MineWndProc** | 142 | `int32_t MineWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **StartTutor** | 144 | `void StartTutor(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **PopupMineralScanChoices** | 145 | `void PopupMineralScanChoices(uint16_t, int16_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **InvertPaneBorder** | 146 | `POINT InvertPaneBorder(uint16_t, int16_t, POINT, POINT *)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FAddWayPoint** | 153 | `int16_t FAddWayPoint(POINT, SCAN *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DestroyAllIshdef** | 155 | `void DestroyAllIshdef(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **BringUpHostDlg** | 176 | `void BringUpHostDlg(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **HostTimerProc** | 179 | `void HostTimerProc(uint16_t, uint16_t, uint16_t, uint32_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **DrawProductionDlg** | 180 | `void DrawProductionDlg(uint16_t, uint16_t, RECT *, int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **IWarpBestForWaypoint** | 186 | `int16_t IWarpBestForWaypoint(FLEET *32, ORDER *32)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ClickInPlanetOrders** | 207 | `uint16_t ClickInPlanetOrders(POINT, int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **EstimateItemProdSched** | 209 | `void EstimateItemProdSched(PLANET *32, PLPROD *32, int16_t, int16_t *, int16_t *)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **ProductionDlg** | 215 | `int16_t ProductionDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **PlanetClick** | 221 | `void PlanetClick(int16_t, int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FFindNearestObject** | 230 | `int16_t FFindNearestObject(POINT, int16_t, SCAN *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **EstMineralsMined** | 232 | `void EstMineralsMined(PLANET *32, int32_t *, int32_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **FHandleMeasuringTape** | 247 | `int16_t FHandleMeasuringTape(SCAN *, POINT)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ExecuteReportClick** | 250 | `void ExecuteReportClick(POINT, int16_t, int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FHandleKey** | 252 | `int16_t FHandleKey(uint16_t, int16_t, int16_t, uint32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **TransferStuff** | 263 | `int16_t TransferStuff(int16_t, int16_t, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawShipOrders** | 265 | `void DrawShipOrders(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FDamageTok** | 296 | `int16_t FDamageTok(TOK *32, int16_t, int32_t *, int32_t, uint16_t, int16_t, int32_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DumpFleets** | 308 | `void DumpFleets(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ExecuteButton** | 311 | `void ExecuteButton(int16_t, int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **UpdateResearchStatus** | 320 | `void UpdateResearchStatus(int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **TbWndProc** | 323 | `int32_t TbWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **DumpPlanets** | 329 | `void DumpPlanets(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ReportDlg** | 332 | `int32_t ReportDlg(uint16_t, uint16_t, uint16_t, int32_t)` |  | [report.c](../decompiled/all/report.c) |
| ⬜ | **FDoCoolBattle** | 356 | `int16_t FDoCoolBattle(FLEET *32, int16_t, uint16_t *, uint16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **MineClick** | 377 | `void MineClick(int16_t, int16_t, int16_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **Produce** | 392 | `void Produce(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **NewGameWizard** | 416 | `void NewGameWizard(uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **ShipCommandProc** | 457 | `void ShipCommandProc(uint16_t, uint16_t, int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **NewGameDlg2** | 464 | `int16_t NewGameDlg2(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **GenNewGameFromFile** | 482 | `int16_t GenNewGameFromFile(char *)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **ResearchDlg** | 482 | `int16_t ResearchDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **ScannerWndProc** | 495 | `int32_t ScannerWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FWriteDataFile** | 499 | `int16_t FWriteDataFile(char *, int16_t, int16_t)` | [save.c](../save.c) | [io.c](../decompiled/all/io.c) |
| ⬜ | **DoThingInteractions** | 525 | `void DoThingInteractions(int16_t)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **FBuildObject** | 530 | `int16_t FBuildObject(PLANET *32, int16_t, int16_t, int16_t, int32_t *)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **FHandleWayPointDrag** | 572 | `int16_t FHandleWayPointDrag(POINT)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ClickInShipOrders** | 607 | `uint16_t ClickInShipOrders(POINT, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FGenerateTurn** | 634 | `int16_t FGenerateTurn(void)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **PlanetWndProc** | 668 | `int32_t PlanetWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ProdCommandHandler** | 678 | `void ProdCommandHandler(uint16_t, uint16_t, int32_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FAttack** | 713 | `int16_t FAttack(int16_t, int16_t, BTLREC *32, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawReportItem** | 766 | `void DrawReportItem(uint16_t, RECT *, int16_t, int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ICompReport** | 802 | `int16_t ICompReport(void *, void *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **MessageWndProc** | 815 | `int32_t MessageWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FRunLogRecord** | 822 | `int16_t FRunLogRecord(int16_t, int16_t, uint8_t *32)` | [log.c](../log.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **MoveFleets** | 846 | `void MoveFleets(void)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **DrawShipWayPtOrders** | 892 | `void DrawShipWayPtOrders(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawMineSurvey** | 1000 | `void DrawMineSurvey(uint16_t, RECT *)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **SlotDlg** | 1157 | `int16_t SlotDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **CommandHandler** | 1188 | `void CommandHandler(uint16_t, uint16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **GenerateWorld** | 1556 | `int16_t GenerateWorld(int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **SatisfyOrders** | 1687 | `void SatisfyOrders(int16_t)` | [turn3.c](../turn3.c) | [turn.c](../decompiled/all/turn.c) |

### Implemented (6)

<details><summary>Show 6 implemented functions</summary>

| | Function | Lines | Source |
|---|----------|------:|--------|
| ✅ | FLoadGame | 1223 | [file.c](../file.c) |
| ✅ | FOpenGame | 216 | [mdi.c](../mdi.c) |
| ✅ | FrameWndProc | 669 | [mdi.c](../mdi.c) |
| ✅ | HostModeDialog | 308 | [mdi.c](../mdi.c) |
| ✅ | TitleWndProc | 334 | [mdi.c](../mdi.c) |
| ✅ | WinMain | 338 | [winmain.c](../winmain.c) |

</details>

