# Implementation Plan

Auto-generated cross-reference of call graph depth and implementation status.

*AI functions excluded (103 functions from ai.c, ai2.c, ai3.c, ai4.c, aiu.c, aiutil.c)*

## Summary

| Depth | Label | Total | Implemented | Unimplemented |
|-------|-------|------:|------------:|--------------:|
| 0 | Depth 0 — Leaf Functions | 192 | 155 | 37 |
| 1 | Depth 1 — Calls Only Leaves | 73 | 47 | 26 |
| 2 | Depth 2 | 76 | 42 | 34 |
| 3 | Depth 3 | 59 | 27 | 32 |
| 4 | Depth 4 | 46 | 17 | 29 |
| 5 | Depth 5 | 19 | 4 | 15 |
| 6 | Depth 6 | 10 | 4 | 6 |
| 7 | Depth 7 | 15 | 8 | 7 |
| 8 | Depth 8 | 15 | 8 | 7 |
| 9 | Depth 9 | 26 | 20 | 6 |
| 10 | Depth 10 | 14 | 12 | 2 |
| 11 | Depth 11 | 14 | 13 | 1 |
| 12 | Depth 12 | 20 | 12 | 8 |
| 13 | Depth 13 | 14 | 8 | 6 |
| 14 | Depth 14 | 13 | 9 | 4 |
| 15 | Depth 15 | 9 | 4 | 5 |
| 16 | Depth 16 | 8 | 5 | 3 |
| 17 | Depth 17 | 11 | 3 | 8 |
| 18 | Depth 18 | 2 | 0 | 2 |
| -1 | Depth -1 — Cyclic Functions | 107 | 41 | 66 |
| | **Total** | **743** | **439** | **304** |

## Depth 0 — Leaf Functions

### Unimplemented (37)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **InitBtnTrack** | 27 | W | `void InitBtnTrack(BTNT *, uint16_t, uint16_t, RECT *, int16_t, int16_t, int16_t, int16_t, char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **IrcRaceDlgHitTest** | 28 | W | `int16_t IrcRaceDlgHitTest(POINT)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DxOfBtn** | 31 | W | `int16_t DxOfBtn(int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **HtMsgBox** | 32 | W | `int16_t HtMsgBox(POINT)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **OrderInfoDlg** | 32 | W | `int16_t OrderInfoDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **DrawFuzzyBorder** | 33 | W | `void DrawFuzzyBorder(uint16_t, RECT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DrawSelectionArrow** | 33 | W | `void DrawSelectionArrow(uint16_t, RECT *, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **FCheckScanner** | 33 | W | `int16_t FCheckScanner(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **HfontPrinterCreate** | 34 | W | `uint16_t HfontPrinterCreate(uint16_t, int16_t, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FCheckShipBuilder** | 35 | W | `int16_t FCheckShipBuilder(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FillFleetCompLB** | 36 | W | `void FillFleetCompLB(void)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawScanXorLines** | 39 | W | `void DrawScanXorLines(uint16_t, POINT *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FCheckSummary** | 39 | W | `int16_t FCheckSummary(uint16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **PanicDlg** | 39 | W | `int16_t PanicDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **GetDxDyOrientation** | 40 | W | `void GetDxDyOrientation(int16_t, int16_t, POINT *, POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **LFetchScoreXVal** | 40 | W | `int32_t LFetchScoreXVal(SCOREX *32, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FGetMouseMove** | 41 | W | `int16_t FGetMouseMove(POINT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FGetRMouseMove** | 41 | W | `int16_t FGetRMouseMove(POINT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **InvalidateAdvPtsRect** | 41 | W | `void InvalidateAdvPtsRect(uint16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **Delay** | 46 | W | `void Delay(int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **NewPlanNameDlg** | 47 | W | `int16_t NewPlanNameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **HcrsFromFrameWindowPt** | 51 | W | `uint16_t HcrsFromFrameWindowPt(POINT, int16_t *)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FOtherStuffAtScanSel** | 52 | W | `int16_t FOtherStuffAtScanSel(void)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **FCheckTemplate** | 57 | W | `int16_t FCheckTemplate(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FGetNextObjHere** | 60 | W | `int16_t FGetNextObjHere(SCAN *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FIsButtonDown** | 60 | W | `int16_t FIsButtonDown(int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FDestIsWP0** | 62 | W | `int16_t FDestIsWP0(FLEET *32)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **SetHScrollBar** | 64 | W | `void SetHScrollBar(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **SetFilteringGroups** | 73 |  | `void SetFilteringGroups(int16_t, int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FLookupOrbitingXfer** | 74 |  | `int16_t FLookupOrbitingXfer(int16_t, int16_t, XFER *, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **FDoesPrimaryTargetTypeExist** | 84 |  | `int16_t FDoesPrimaryTargetTypeExist(TOK *32, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **TerminateToolbarFocus** | 93 | W | `void TerminateToolbarFocus(int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **LinkFleets** | 103 |  | `void LinkFleets(int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DiaganolTextOut** | 131 | W | `void DiaganolTextOut(uint16_t, RECT *, char *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FIntersectCircleLine** | 135 |  | `int16_t FIntersectCircleLine(POINT, POINT, POINT, int32_t, int16_t, int16_t *, int16_t *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DrawRadarCircle** | 163 | W | `void DrawRadarCircle(DRAWCIR *, RECT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **AnimateAttack** | 436 | W | `void AnimateAttack(uint16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |

### Implemented (155)

<details><summary>Show 155 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | AddBackTrailingSpaces | 13 |  | [utilgen.c](../utilgen.c) |
| ✅ | AskSaveDialog | 34 | W | [file.c](../file.c) |
| ✅ | BoundPoints | 38 |  | [utilgen.c](../utilgen.c) |
| ✅ | BoundsCheckPlayer | 56 |  | [race.c](../race.c) |
| ✅ | BtlDataGet | 50 |  | [vcr.c](../vcr.c) |
| ✅ | CBattleKills | 43 |  | [vcr.c](../vcr.c) |
| ✅ | CBattles | 44 |  | [vcr.c](../vcr.c) |
| ✅ | CParseNumbers | 49 |  | [utilgen.c](../utilgen.c) |
| ✅ | CPlanetsInCircle | 64 |  | [thing.c](../thing.c) |
| ✅ | CancelMemRt | 14 |  | [log.c](../log.c) |
| ✅ | CchTutorString | 58 |  | [tutor2.c](../tutor2.c) |
| ✅ | ChFromNybble | 33 |  | [utilgen.c](../utilgen.c) |
| ✅ | ChopLastWord | 19 |  | [utilgen.c](../utilgen.c) |
| ✅ | ChopTrailingSpaces | 13 |  | [utilgen.c](../utilgen.c) |
| ✅ | ClearFile | 23 |  | [util.c](../util.c) |
| ✅ | CommaFormatLong | 46 |  | [utilgen.c](../utilgen.c) |
| ✅ | CreateBackupDir | 30 |  | [turn2.c](../turn2.c) |
| ✅ | CreateShip | 31 |  | [turn2.c](../turn2.c) |
| ✅ | CshQueued | 53 |  | [ship.c](../ship.c) |
| ✅ | CtrTextOut | 18 | W | [utilgen.c](../utilgen.c) |
| ✅ | DGetDistance | 25 |  | [util.c](../util.c) |
| ✅ | DeleteWpFar | 69 |  | [ship.c](../ship.c) |
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
| ✅ | FAttackPlayer | 30 |  | [battle.c](../battle.c) |
| ✅ | FBadFileError | 19 |  | [file.c](../file.c) |
| ✅ | FBogusLong | 18 |  | [file.c](../file.c) |
| ✅ | FCanMerge | 45 |  | [ship.c](../ship.c) |
| ✅ | FCanSplit | 19 |  | [ship.c](../ship.c) |
| ✅ | FCanSplitAll | 24 |  | [ship.c](../ship.c) |
| ✅ | FCheckBtlPlan | 23 | W | [tutor.c](../tutor.c) |
| ✅ | FCheckResearch | 18 | W | [tutor.c](../tutor.c) |
| ✅ | FColonizer | 25 |  | [ship2.c](../ship2.c) |
| ✅ | FFindPlayerMessage | 22 |  | [msg.c](../msg.c) |
| ✅ | FFleetCanJumpgate | 41 |  | [util.c](../util.c) |
| ✅ | FFuelTanker | 17 |  | [battle.c](../battle.c) |
| ✅ | FGetNMsgbig | 58 |  | [msg.c](../msg.c) |
| ✅ | FGetPrevLogRt | 27 |  | [log.c](../log.c) |
| ✅ | FHandleChar | 23 | W | [stars.c](../stars.c) |
| ✅ | FHullHasBombs | 30 |  | [battle.c](../battle.c) |
| ✅ | FHullHasTeeth | 24 |  | [battle.c](../battle.c) |
| ✅ | FIsTargetOfMdTarget | 45 |  | [battle.c](../battle.c) |
| ✅ | FProdIsTerra | 30 |  | [planet.c](../planet.c) |
| ✅ | FQueueColonistDrop | 47 |  | [turn2.c](../turn2.c) |
| ✅ | FRemovePlayerMessage | 26 |  | [msg.c](../msg.c) |
| ✅ | FScout | 25 |  | [ship2.c](../ship2.c) |
| ✅ | FShouldPartBeHidden | 73 |  | [research.c](../research.c) |
| ✅ | FStringFitsScreen | 29 | W | [utilgen.c](../utilgen.c) |
| ✅ | FakeEditProc | 17 | W | [ship.c](../ship.c) |
| ✅ | FreeHb | 29 |  | [memory.c](../memory.c) |
| ✅ | FreeHbr | 27 | W | [utilgen.c](../utilgen.c) |
| ✅ | FreeLpth | 14 |  | [thing.c](../thing.c) |
| ✅ | GetASubMenu | 44 | W | [mdi.c](../mdi.c) |
| ✅ | GetFileSeeds | 18 |  | [utilgen.c](../utilgen.c) |
| ✅ | GetMineFieldCounts | 29 |  | [mine.c](../mine.c) |
| ✅ | GetRaceGrbit | 19 |  | [race.c](../race.c) |
| ✅ | GetRaceStat | 10 |  | [race.c](../race.c) |
| ✅ | GetTrueHullCost | 16 |  | [util.c](../util.c) |
| ✅ | GetVCCheck | 10 |  | [create.c](../create.c) |
| ✅ | GetVCVal | 55 |  | [create.c](../create.c) |
| ✅ | GetWindowRc | 21 | W | [mdi.c](../mdi.c) |
| ✅ | HandleFocusState | 18 | W | [planet.c](../planet.c) |
| ✅ | HbrGet | 44 | W | [utilgen.c](../utilgen.c) |
| ✅ | HideProgressGauge | 14 | W | [utilgen.c](../utilgen.c) |
| ✅ | HpalBlackReserved | 28 | W | [utilgen.c](../utilgen.c) |
| ✅ | ICompFleetPoint | 32 |  | [util.c](../util.c) |
| ✅ | ICompFleetPoint2 | 26 |  | [util.c](../util.c) |
| ✅ | ICompLong | 10 |  | [utilgen.c](../utilgen.c) |
| ✅ | IEmptyBmpFromGrhst | 21 |  | [build.c](../build.c) |
| ✅ | IRaceChecksum | 19 |  | [race.c](../race.c) |
| ✅ | IStargateFromLppl | 29 |  | [util.c](../util.c) |
| ✅ | IValidateWormholePos | 138 |  | [thing.c](../thing.c) |
| ✅ | IWarpMAFromLppl | 55 |  | [planet.c](../planet.c) |
| ✅ | IdmGiveTraderPart | 68 |  | [thing.c](../thing.c) |
| ✅ | IflFromLpfl | 22 |  | [util.c](../util.c) |
| ✅ | InitBattlePlan | 33 |  | [create.c](../create.c) |
| ✅ | InitMDIApp | 176 | W | [mdi.c](../mdi.c) |
| ✅ | InitNewGame3 | 10 |  | [create.c](../create.c) |
| ✅ | InitTiles | 44 | W | [init.c](../init.c) |
| ✅ | IntToRoman | 42 |  | [utilgen.c](../utilgen.c) |
| ✅ | IshFindSimilarDesign | 43 |  | [util.c](../util.c) |
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
| ✅ | MarkPlayersThatSentMsgs | 28 |  | [msg.c](../msg.c) |
| ✅ | NoAutoTrackFleet | 55 |  | [ship2.c](../ship2.c) |
| ✅ | NthValidEnemyShdef | 44 |  | [build.c](../build.c) |
| ✅ | NthValidShdef | 35 |  | [build.c](../build.c) |
| ✅ | NybbleFromCh | 42 |  | [utilgen.c](../utilgen.c) |
| ✅ | OffsetRc | 14 |  | [utilgen.c](../utilgen.c) |
| ✅ | OutputFileString | 35 |  | [utilgen.c](../utilgen.c) |
| ✅ | PackageUpMsg | 60 |  | [msg.c](../msg.c) |
| ✅ | PctPlanetDesirability | 108 |  | [planet.c](../planet.c) |
| ✅ | PctTerraFromLpfl | 46 |  | [ship2.c](../ship2.c) |
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
| ✅ | Randomize | 23 |  | [utilgen.c](../utilgen.c) |
| ✅ | Randomize2 | 25 |  | [utilgen.c](../utilgen.c) |
| ✅ | RcCtrTextOut | 32 | W | [utilgen.c](../utilgen.c) |
| ✅ | ReadBigBlock | 32 |  | [utilgen.c](../utilgen.c) |
| ✅ | ReadIniTileSettings | 86 | W | [init.c](../init.c) |
| ✅ | ResetHb | 24 |  | [memory.c](../memory.c) |
| ✅ | ResetMessages | 22 |  | [msg.c](../msg.c) |
| ✅ | ScanToPt | 39 |  | [scan.c](../scan.c) |
| ✅ | ScoreFromGiveAndTakeAndTactic | 40 |  | [battle.c](../battle.c) |
| ✅ | SetFileSeeds | 12 |  | [utilgen.c](../utilgen.c) |
| ✅ | SetRaceGrbit | 26 |  | [race.c](../race.c) |
| ✅ | SetRaceStat | 17 |  | [race.c](../race.c) |
| ✅ | SetSzWorkFromDt | 44 |  | [save.c](../save.c) |
| ✅ | SetVCCheck | 18 |  | [create.c](../create.c) |
| ✅ | ShowTutor | 21 | W | [tutor.c](../tutor.c) |
| ✅ | StickyDlgPos | 43 | W | [utilgen.c](../utilgen.c) |
| ✅ | StreamClose | 14 |  | [file.c](../file.c) |
| ✅ | TechStatus | 43 |  | [parts.c](../parts.c) |
| ✅ | UnmarkMineFields | 22 |  | [turn2.c](../turn2.c) |
| ✅ | UpdateBattleRecords | 63 |  | [file.c](../file.c) |
| ✅ | WPackLong | 19 |  | [util.c](../util.c) |
| ✅ | WtFromLpfl | 31 |  | [util.c](../util.c) |

</details>

## Depth 1 — Calls Only Leaves

### Unimplemented (26)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **GetXferLeftRightRcs** | 16 | W | `void GetXferLeftRightRcs(RECT *, RECT *, RECT *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **LogicalToScan** | 16 | W | `void LogicalToScan(POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ScanToLogical** | 22 | W | `void ScanToLogical(POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ItbFromPpt** | 27 | W | `int16_t ItbFromPpt(POINT *)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FCheckPlanetRoute** | 31 | W | `int16_t FCheckPlanetRoute(int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **GetScanFleetOrientation** | 32 | W | `void GetScanFleetOrientation(FLEET *32, POINT *, POINT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DrawLockLight** | 34 | W | `void DrawLockLight(uint16_t, RECT *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **Draw3dFrame** | 44 | W | `void Draw3dFrame(uint16_t, RECT *, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **ShowMainControls** | 48 | W | `void ShowMainControls(uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **HostOptionsDialog** | 50 | W | `int16_t HostOptionsDialog(uint16_t, uint16_t, uint16_t, int32_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FCheckSelection** | 53 | W | `int16_t FCheckSelection(uint16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **RandomSeedDlg** | 55 | W | `int16_t RandomSeedDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **LDrawGauge** | 64 | W | `int32_t LDrawGauge(uint16_t, RECT *, int16_t, int32_t *, uint16_t *, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **InvalidateMineralBars** | 66 | W | `void InvalidateMineralBars(void)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **RenameZipDlg** | 66 | W | `int16_t RenameZipDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DrawABunchOfStars** | 68 | W | `void DrawABunchOfStars(uint16_t, RECT *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **RenameDlg** | 72 | W | `int16_t RenameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **WrapTextOut** | 72 | W | `void WrapTextOut(uint16_t, int16_t *, int16_t *, char *, int16_t, int16_t, int16_t, int16_t *, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FPacketDecay** | 76 |  | `int16_t FPacketDecay(THING *32, int16_t)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **CTorpHit** | 79 |  | `int32_t CTorpHit(int32_t, TOK *32, int16_t, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **InitScoreDlg** | 80 | W | `void InitScoreDlg(uint16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FValidSerialNo** | 82 |  | `int16_t FValidSerialNo(char *, int32_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **GetVCRStats** | 102 | W | `void GetVCRStats(int16_t, int32_t *, DV *, int32_t *, int16_t *)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **PtDisplayZipOrdInfo** | 127 | W | `POINT PtDisplayZipOrdInfo(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **GetShdefScannerRange** | 184 |  | `int16_t GetShdefScannerRange(SHDEF *32, int16_t, int16_t *, int16_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawBtn** | 258 | W | `void DrawBtn(uint16_t, RECT *, int16_t, int16_t, char *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |

### Implemented (47)

<details><summary>Show 47 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CMaxDefenses | 34 |  | [planet.c](../planet.c) |
| ✅ | CchGetString | 22 |  | [utilgen.c](../utilgen.c) |
| ✅ | DecorateHullName | 46 |  | [util.c](../util.c) |
| ✅ | FCanKillTok | 42 |  | [battle.c](../battle.c) |
| ✅ | FCheckPassword | 35 |  | [utilgen.c](../utilgen.c) |
| ✅ | FCompressUserString | 57 |  | [utilgen.c](../utilgen.c) |
| ✅ | FDecompressUserString | 65 |  | [utilgen.c](../utilgen.c) |
| ✅ | FFleetHasTeeth | 27 |  | [battle.c](../battle.c) |
| ✅ | FGetSystemColors | 88 | W | [stars.c](../stars.c) |
| ✅ | FLookupPart | 352 |  | [parts.c](../parts.c) |
| ✅ | FSendPlrMsg | 26 |  | [msg.c](../msg.c) |
| ✅ | FSendPrependedPlrMsg | 26 |  | [msg.c](../msg.c) |
| ✅ | FValidSerialLong | 41 |  | [file.c](../file.c) |
| ✅ | FormatSerialAndEnv | 90 |  | [mdi.c](../mdi.c) |
| ✅ | FreeLp | 29 |  | [memory.c](../memory.c) |
| ✅ | GetFileStatus | 15 |  | [file.c](../file.c) |
| ✅ | GetTechLevelCost | 40 |  | [research.c](../research.c) |
| ✅ | GetTruePartCost | 113 |  | [ship.c](../ship.c) |
| ✅ | HdibLoadBigResource | 38 | W | [utilgen.c](../utilgen.c) |
| ✅ | HpalFromDib | 45 | W | [utilgen.c](../utilgen.c) |
| ✅ | IFindIdealWarp | 68 |  | [ship.c](../ship.c) |
| ✅ | IdmGetMessageN | 17 |  | [msg.c](../msg.c) |
| ✅ | InitializeMenu | 95 | W | [mdi.c](../mdi.c) |
| ✅ | LCalcFuelGainFromRamScoops | 77 |  | [util.c](../util.c) |
| ✅ | LInnateRaceHabitability | 250 |  | [race.c](../race.c) |
| ✅ | LdpFromItokDv | 47 |  | [vcr.c](../vcr.c) |
| ✅ | LphuldefFromId | 17 |  | [parts.c](../parts.c) |
| ✅ | MakeNewName | 26 |  | [build.c](../build.c) |
| ✅ | MarkPlanetsPlayerLost | 48 |  | [msg.c](../msg.c) |
| ✅ | PaletteSize | 20 | W | [utilgen.c](../utilgen.c) |
| ✅ | PctTrueMaxGrowth | 18 |  | [race.c](../race.c) |
| ✅ | PszCalcEnvVar | 25 |  | [planet.c](../planet.c) |
| ✅ | PszFleetNameFromWord | 37 |  | [util.c](../util.c) |
| ✅ | PszFromLongK | 44 |  | [utilgen.c](../utilgen.c) |
| ✅ | PszGetDistance | 34 |  | [util.c](../util.c) |
| ✅ | PszGetPlanetName | 24 |  | [util.c](../util.c) |
| ✅ | RandomizeTokOrder | 61 |  | [battle.c](../battle.c) |
| ✅ | RefitFrameChildren | 129 | W | [mdi.c](../mdi.c) |
| ✅ | SetFileXorStream | 29 |  | [utilgen.c](../utilgen.c) |
| ✅ | SetScanScrollBars | 44 | W | [scan.c](../scan.c) |
| ✅ | SetVCVal | 23 |  | [create.c](../create.c) |
| ✅ | SetVisPFFinish | 71 |  | [save.c](../save.c) |
| ✅ | SetWindowIniString | 52 | W | [mdi.c](../mdi.c) |
| ✅ | SortReportCache | 95 | W | [report.c](../report.c) |
| ✅ | SzVersion | 20 |  | [util.c](../util.c) |
| ✅ | WFromLpfl | 20 |  | [util.c](../util.c) |
| ✅ | XorFileBuf | 32 |  | [utilgen.c](../utilgen.c) |

</details>

## Depth 2 — Calls up to depth 1

### Unimplemented (34)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **SetNGWTitle** | 17 | W | `void SetNGWTitle(uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **SetRCWTitle** | 17 | W | `void SetRCWTitle(uint16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **FIsPopupHullType** | 22 | W | `int16_t FIsPopupHullType(int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **FillBattleDD** | 23 | W | `void FillBattleDD(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **PtDisplayString** | 23 | W | `POINT PtDisplayString(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **FillZipProdLB** | 46 | W | `void FillZipProdLB(uint16_t, ZIPPRODQ *)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **DrawMassWarpGauge** | 49 | W | `void DrawMassWarpGauge(uint16_t, RECT *, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FillBuildPartsLB** | 50 | W | `void FillBuildPartsLB(uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **UpdateSlotGlobals** | 50 | W | `void UpdateSlotGlobals(void)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FDrawTileNC** | 52 | W | `int16_t FDrawTileNC(uint16_t, TILE *, RECT *, char *)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **IdFindAdjStarbase** | 53 | W | `int16_t IdFindAdjStarbase(int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FTrackBtn** | 61 | W | `int16_t FTrackBtn(BTNT *)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **DrawThingGauge** | 72 | W | `void DrawThingGauge(uint16_t, RECT *, THING *32, int16_t)` | [thing.c](../thing.c) | [thing.c](../decompiled/all/thing.c) |
| ⬜ | **DrawTutorText** | 72 | W | `void DrawTutorText(uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **PtDisplayResourceInfo** | 75 | W | `POINT PtDisplayResourceInfo(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **CMineSweepFromLphul** | 76 |  | `int32_t CMineSweepFromLphul(HUL *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **CShipsScanVis** | 76 | W | `int32_t CShipsScanVis(FLEET *32)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FMatchTarget** | 80 |  | `int16_t FMatchTarget(FLEET *32, int16_t, int16_t)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **CLayMinesFromLpfl** | 89 |  | `int32_t CLayMinesFromLpfl(FLEET *32, int16_t, int16_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DrawPlanShip** | 91 | W | `void DrawPlanShip(uint16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **About** | 92 | W | `int16_t About(uint16_t, uint16_t, uint16_t, int32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **InvalidateReport** | 94 |  | `void InvalidateReport(int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **PtDisplayFactoryMineInfo** | 96 | W | `POINT PtDisplayFactoryMineInfo(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **MarkTechsSeen** | 98 |  | `void MarkTechsSeen(HUL *32, int16_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DecorateMsgTitleBar** | 100 | W | `void DecorateMsgTitleBar(uint16_t, RECT *)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **HealShips** | 124 |  | `void HealShips(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **KillUsedWaypoints** | 125 |  | `void KillUsedWaypoints(void)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DxReportColHdr** | 138 | W | `int16_t DxReportColHdr(int16_t, int16_t, char *, uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **DpFromPtokBrcToBrc** | 161 |  | `int32_t DpFromPtokBrcToBrc(TOK *32, uint8_t, uint8_t, TOK *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PszGetTaskName** | 178 |  | `char * PszGetTaskName(FLEET *32, int16_t *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FCalcFleetBombDamage** | 187 |  | `int16_t FCalcFleetBombDamage(FLEET *32, int32_t *, int32_t *, int32_t *, int32_t *, int32_t *, int16_t *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **TooltipWndProc** | 208 | W | `int32_t TooltipWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **PtDisplayPlanetStateInfo** | 252 | W | `POINT PtDisplayPlanetStateInfo(uint16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **DrawShipScanPath** | 337 | W | `void DrawShipScanPath(uint16_t, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |

### Implemented (42)

<details><summary>Show 42 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CAdvantagePoints | 315 |  | [race.c](../race.c) |
| ✅ | CBattleUnits | 71 |  | [vcr.c](../vcr.c) |
| ✅ | CMineFromLpfl | 57 |  | [ship2.c](../ship2.c) |
| ✅ | CPtsCloakFromLphs | 69 |  | [ship2.c](../ship2.c) |
| ✅ | CostOfDevelopingItem | 64 |  | [research.c](../research.c) |
| ✅ | CplrBattle | 269 |  | [battle.c](../battle.c) |
| ✅ | DibBlt | 34 | W | [utilgen.c](../utilgen.c) |
| ✅ | DibFromBitmap | 157 | W | [utilgen.c](../utilgen.c) |
| ✅ | DiscoverNewMinerals | 34 |  | [turn2.c](../turn2.c) |
| ✅ | DpShieldOfShdef | 68 |  | [util.c](../util.c) |
| ✅ | FCanBuildShdef | 52 |  | [util.c](../util.c) |
| ✅ | FCanTerraformLppl | 183 |  | [planet.c](../planet.c) |
| ✅ | FCreateFonts | 77 | W | [init.c](../init.c) |
| ✅ | FFleetHasBombs | 35 |  | [battle.c](../battle.c) |
| ✅ | FGetBestDefensePart | 34 |  | [planet.c](../planet.c) |
| ✅ | FGetNewGameName | 67 | W | [create.c](../create.c) |
| ✅ | FLookupPartX | 16 |  | [parts.c](../parts.c) |
| ✅ | FSendPlrMsg2 | 13 |  | [msg.c](../msg.c) |
| ✅ | FSerialAndEnvFromSz | 117 |  | [mdi.c](../mdi.c) |
| ✅ | FreePl | 13 |  | [memory.c](../memory.c) |
| ✅ | FreeStuff | 180 | W | [init.c](../init.c) |
| ✅ | GetDiskSerialNumber | 104 |  | [utilgen.c](../utilgen.c) |
| ✅ | GetFleetScannerRange | 53 |  | [util.c](../util.c) |
| ✅ | GetIniWinRc | 71 | W | [init.c](../init.c) |
| ✅ | GetProductionCosts | 380 |  | [produce.c](../produce.c) |
| ✅ | IMsgNext | 31 |  | [msg.c](../msg.c) |
| ✅ | IMsgPrev | 32 |  | [msg.c](../msg.c) |
| ✅ | IPlrAlsoCheater | 27 |  | [stars.c](../stars.c) |
| ✅ | InitFromHuldef | 62 |  | [battle.c](../battle.c) |
| ✅ | InitNewGamePlr | 140 |  | [create.c](../create.c) |
| ✅ | LookupBestPlanetaryScanner | 25 |  | [parts.c](../parts.c) |
| ✅ | MdCalcStargateDamage | 116 |  | [ship2.c](../ship2.c) |
| ✅ | OutputSz | 29 |  | [util.c](../util.c) |
| ✅ | PctJammerFromHul | 82 |  | [build.c](../build.c) |
| ✅ | PszNameProdItem | 77 |  | [produce.c](../produce.c) |
| ✅ | PszPlayerName | 72 |  | [util.c](../util.c) |
| ✅ | RightTextOut | 32 | W | [utilgen.c](../utilgen.c) |
| ✅ | StargateRangeFromLppl | 46 |  | [planet.c](../planet.c) |
| ✅ | UnpackBattlePlan | 30 |  | [file.c](../file.c) |
| ✅ | UpdateShdefCost | 97 |  | [util.c](../util.c) |
| ✅ | WriteIniSettings | 302 | W | [mdi.c](../mdi.c) |
| ✅ | WtMaxShdefStat | 48 |  | [ship.c](../ship.c) |

</details>

## Depth 3 — Calls up to depth 2

### Unimplemented (32)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **DrawShipPlanet** | 6 | W | `void DrawShipPlanet(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawMineralItem** | 27 | W | `void DrawMineralItem(uint16_t, int16_t, int16_t, int16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **SetFleetDropDownSel** | 38 | W | `void SetFleetDropDownSel(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FCheckMessages** | 42 | W | `int16_t FCheckMessages(int16_t, int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FillProdSrcLB** | 54 | W | `void FillProdSrcLB(uint16_t, int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **DrawBitmapButton** | 59 | W | `void DrawBitmapButton(uint16_t, POINT, int16_t, int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **RestoreGameState** | 66 | W | `void RestoreGameState(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **DrawDlgLBEntireItem** | 71 | W | `void DrawDlgLBEntireItem(DRAWITEMSTRUCT *32, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DrawProgressGauge** | 72 | W | `void DrawProgressGauge(uint16_t, int16_t, int16_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **ReflowColumn** | 74 | W | `void ReflowColumn(int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawRaceAdvantagePoints** | 79 | W | `void DrawRaceAdvantagePoints(uint16_t, RECT *, PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawFleetBitmap** | 98 | W | `void DrawFleetBitmap(FLEET *32, uint16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawPlanetXferSide** | 102 | W | `void DrawPlanetXferSide(uint16_t, RECT *, PLANET *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawScanFleetCount** | 108 | W | `void DrawScanFleetCount(FLEET *32, int16_t, int16_t, uint16_t, uint16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DzMoveRangeToConsider** | 111 |  | `int16_t DzMoveRangeToConsider(TOK *32, uint16_t, uint8_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawNewGame3** | 130 | W | `void DrawNewGame3(uint16_t, uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **PctCloakFromLpfl** | 131 |  | `int16_t PctCloakFromLpfl(FLEET *32)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **DrawNewGame2** | 137 | W | `void DrawNewGame2(uint16_t, uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **DrawScoreReport** | 154 | W | `void DrawScoreReport(uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ScoreGuessBattleDamage** | 156 |  | `int32_t ScoreGuessBattleDamage(TOK *32, uint8_t, int16_t, uint16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **FillBuildDD** | 167 | W | `void FillBuildDD(uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **ShowTooltip** | 179 | W | `void ShowTooltip(int16_t, RECT *)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **ValidateWaypoints** | 182 |  | `void ValidateWaypoints(void)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawProductionItem** | 184 | W | `void DrawProductionItem(uint16_t, RECT *, char *, int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawVCReport** | 195 | W | `void DrawVCReport(uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CheckWeapons** | 202 |  | `void CheckWeapons(TOK *32, int16_t *, uint8_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DrawPlanetStarbase** | 207 | W | `void DrawPlanetStarbase(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **NewGameDlg** | 219 | W | `int16_t NewGameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **DrawBuildSelComp** | 220 | W | `void DrawBuildSelComp(uint16_t, uint16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **DrawHistoryReport** | 274 | W | `void DrawHistoryReport(uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CreateRandomRace** | 336 |  | `void CreateRandomRace(PLAYER *)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawResearchDlg** | 891 | W | `void DrawResearchDlg(uint16_t, uint16_t, RECT *, int16_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |

### Implemented (27)

<details><summary>Show 27 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | AlertSz | 28 |  | [utilgen.c](../utilgen.c) |
| ✅ | AutoFleetOrder | 69 |  | [ship2.c](../ship2.c) |
| ✅ | AutoTerraform | 74 |  | [turn2.c](../turn2.c) |
| ✅ | CMineSweepFromLpfl | 32 |  | [ship2.c](../ship2.c) |
| ✅ | CheckInitiative | 20 |  | [battle.c](../battle.c) |
| ✅ | CheckTarget | 61 |  | [battle.c](../battle.c) |
| ✅ | CreateChildWindows | 179 | W | [mdi.c](../mdi.c) |
| ✅ | DrawHostDialog2 | 128 | W | [mdi.c](../mdi.c) |
| ✅ | EstFuelUse | 203 |  | [ship.c](../ship.c) |
| ✅ | FReadShDef | 137 |  | [file.c](../file.c) |
| ✅ | FSendPlrMsg2XGen | 55 |  | [msg.c](../msg.c) |
| ✅ | GetCachedFleetScannerRange | 58 |  | [util.c](../util.c) |
| ✅ | GetPlanetScannerRange | 74 |  | [util.c](../util.c) |
| ✅ | IBestTerraform | 79 |  | [planet.c](../planet.c) |
| ✅ | ITechLearnATech | 70 |  | [battle.c](../battle.c) |
| ✅ | IpctCanTerraformLppl | 31 |  | [planet.c](../planet.c) |
| ✅ | LGetFleetStat | 34 |  | [ship.c](../ship.c) |
| ✅ | PctCloakFromHuldef | 77 |  | [planet.c](../planet.c) |
| ✅ | PctPlanetOptValue | 52 |  | [planet.c](../planet.c) |
| ✅ | PszGetFleetName | 63 |  | [util.c](../util.c) |
| ✅ | PszGetThingName | 63 |  | [util.c](../util.c) |
| ✅ | ReadRtPlr | 44 |  | [file.c](../file.c) |
| ✅ | RegenShield | 35 |  | [battle.c](../battle.c) |
| ✅ | SetMsgTitle | 193 | W | [msg.c](../msg.c) |
| ✅ | SpankTheCheaters | 147 |  | [battle.c](../battle.c) |
| ✅ | TossNonAutoBuildItems | 56 |  | [turn2.c](../turn2.c) |
| ✅ | UninhabitPlanet | 51 |  | [planet.c](../planet.c) |

</details>

## Depth 4 — Calls up to depth 3

### Unimplemented (29)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **DrawFleetComp** | 6 | W | `void DrawFleetComp(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetPlanetTitleBar** | 26 | W | `void SetPlanetTitleBar(uint16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **EndTutor** | 27 | W | `void EndTutor(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **DrawToolbar** | 31 | W | `void DrawToolbar(uint16_t, RECT *)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **DrawCBEntireItem** | 44 | W | `void DrawCBEntireItem(DRAWITEMSTRUCT *32, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FTrackNewGameDlg3** | 47 | W | `int16_t FTrackNewGameDlg3(uint16_t, POINT, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **ProgressGaugeDlg** | 53 | W | `int16_t ProgressGaugeDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FillShipDD** | 66 | W | `void FillShipDD(int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawThingXferSide** | 73 | W | `void DrawThingXferSide(uint16_t, RECT *, THING *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetMineralTitleBar** | 73 | W | `void SetMineralTitleBar(uint16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **EnsureTileSize** | 79 | W | `void EnsureTileSize(int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawFleetShipsXferSide** | 83 | W | `void DrawFleetShipsXferSide(uint16_t, RECT *, FLEET *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FuelFleets** | 92 |  | `void FuelFleets(void)` | [turn.c](../turn.c) | [turn.c](../decompiled/all/turn.c) |
| ⬜ | **DrawPlanShipBitmap** | 99 | W | `void DrawPlanShipBitmap(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawFleetGauge** | 109 | W | `void DrawFleetGauge(uint16_t, RECT *, FLEET *32, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetVCRBoard** | 127 | W | `int16_t SetVCRBoard(int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **RaceWizardDlg6** | 129 | W | `int16_t RaceWizardDlg6(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawRace3** | 137 | W | `void DrawRace3(uint16_t, uint16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **RaceWizardDlg4** | 138 | W | `int16_t RaceWizardDlg4(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **RaceWizardDlg5** | 150 | W | `int16_t RaceWizardDlg5(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **UpdateOrdersDDs** | 152 | W | `void UpdateOrdersDDs(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **PopupMenu** | 182 | W | `int16_t PopupMenu(uint16_t, int16_t, int16_t, int16_t, int32_t *, char * *, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **DrawRace2** | 224 | W | `void DrawRace2(uint16_t, uint16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **SweepForMines** | 227 |  | `void SweepForMines(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **DrawSlotDlg** | 257 | W | `void DrawSlotDlg(uint16_t, uint16_t, RECT *, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **RaceWizardDlg1** | 333 | W | `int16_t RaceWizardDlg1(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawVCR** | 535 | W | `void DrawVCR(uint16_t, int16_t, int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **DrawScanner** | 1198 | W | `int16_t DrawScanner(uint16_t, RECT *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DisplayComponentInfo** | 1327 | W | `void DisplayComponentInfo(uint16_t, int16_t, int16_t, PART *)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |

### Implemented (17)

<details><summary>Show 17 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | AutoRouteFleet | 133 |  | [ship2.c](../ship2.c) |
| ✅ | DirtyGame | 13 |  | [log.c](../log.c) |
| ✅ | DxyMoveTokTo | 263 |  | [battle.c](../battle.c) |
| ✅ | FReadPlanet | 203 |  | [file.c](../file.c) |
| ✅ | GetCargoFree | 25 |  | [ship.c](../ship.c) |
| ✅ | GetFuelFree | 15 |  | [ship.c](../ship.c) |
| ✅ | IBestRemoteTerra | 65 |  | [turn2.c](../turn2.c) |
| ✅ | LFuelUseToWaypoint | 116 |  | [ship.c](../ship.c) |
| ✅ | MeteorStrike | 150 |  | [turn2.c](../turn2.c) |
| ✅ | PlanetaryClimateChange | 60 |  | [turn2.c](../turn2.c) |
| ✅ | PszGetLocName | 33 |  | [util.c](../util.c) |
| ✅ | SendBattleMessages | 422 |  | [battle.c](../battle.c) |
| ✅ | SetVisPFFleets | 313 |  | [save.c](../save.c) |
| ✅ | SetVisPFInit | 197 |  | [save.c](../save.c) |
| ✅ | SetVisPFThings | 229 |  | [save.c](../save.c) |
| ✅ | SpdOfShip | 137 |  | [battle.c](../battle.c) |
| ✅ | UpdateProgressGauge | 30 |  | [utilgen.c](../utilgen.c) |

</details>

## Depth 5 — Calls up to depth 4

### Unimplemented (15)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **DrawPlanetShipList** | 6 | W | `void DrawPlanetShipList(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **DrawShipCargo** | 6 | W | `void DrawShipCargo(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetOrdersLbSel** | 30 | W | `void SetOrdersLbSel(int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SetBuildSelection** | 31 | W | `void SetBuildSelection(int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FTrackRaceDlg3** | 47 | W | `int16_t FTrackRaceDlg3(uint16_t, POINT, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **PszGetDestName** | 78 |  | `char * PszGetDestName(FLEET *32, uint16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **PopupVCRMenu** | 87 | W | `int16_t PopupVCRMenu(uint16_t, int16_t, int16_t, uint8_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **ScrollScanner** | 97 | W | `void ScrollScanner(int16_t, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **RemoteTerraforming** | 103 |  | `void RemoteTerraforming(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **NewGameDlg3** | 105 | W | `int16_t NewGameDlg3(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **RedrawScanSel** | 105 | W | `void RedrawScanSel(uint16_t, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DrawFleetCargoXferSide** | 120 | W | `void DrawFleetCargoXferSide(uint16_t, RECT *, FLEET *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ReportColumnPopup** | 149 | W | `void ReportColumnPopup(POINT, int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FTrackRaceDlg2** | 154 | W | `int16_t FTrackRaceDlg2(uint16_t, POINT, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawScannerSBar** | 263 | W | `void DrawScannerSBar(uint16_t, RECT *, SBAR *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |

### Implemented (4)

<details><summary>Show 4 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | LComputePower | 100 |  | [util.c](../util.c) |
| ✅ | PszFormatString | 294 |  | [msg.c](../msg.c) |
| ✅ | SetVisPFPlanets | 394 |  | [save.c](../save.c) |
| ✅ | ShowProgressGauge | 15 |  | [utilgen.c](../utilgen.c) |

</details>

## Depth 6 — Calls up to depth 5

### Unimplemented (6)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **FillOrdersLB** | 41 | W | `void FillOrdersLB(void)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawXferDlg** | 46 | W | `void DrawXferDlg(uint16_t, uint16_t, RECT *, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **CtrPointScan** | 75 | W | `void CtrPointScan(POINT, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **RaceWizardDlg3** | 99 | W | `int16_t RaceWizardDlg3(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **RaceWizardDlg2** | 174 | W | `int16_t RaceWizardDlg2(uint16_t, uint16_t, uint16_t, int32_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **DrawBuildSelHull** | 378 | W | `void DrawBuildSelHull(uint16_t, uint16_t, int16_t, RECT *)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |

### Implemented (4)

<details><summary>Show 4 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | ComputeShdefPowers | 30 |  | [util.c](../util.c) |
| ✅ | PszFormatIds | 14 |  | [msg.c](../msg.c) |
| ✅ | PszFormatMessage | 14 |  | [msg.c](../msg.c) |
| ✅ | SetVisiblePlanFleet | 28 |  | [save.c](../save.c) |

</details>

## Depth 7 — Calls up to depth 6

### Unimplemented (7)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **FAskKillTutor** | 23 | W | `int16_t FAskKillTutor(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **TutorError** | 26 | W | `void TutorError(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FEnsurePointOnScreen** | 50 | W | `int16_t FEnsurePointOnScreen(POINT, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **TutorDlg** | 75 | W | `int16_t TutorDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **PasswordDlg** | 77 | W | `int16_t PasswordDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **FDeleteBattlePlan** | 80 |  | `int16_t FDeleteBattlePlan(int16_t, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **PrintMapDlg** | 146 | W | `int16_t PrintMapDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |

### Implemented (8)

<details><summary>Show 8 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | FileError | 19 |  | [file.c](../file.c) |
| ✅ | LphbAlloc | 56 |  | [memory.c](../memory.c) |
| ✅ | LphbReAlloc | 73 |  | [memory.c](../memory.c) |
| ✅ | PszGetMessageN | 23 |  | [msg.c](../msg.c) |
| ✅ | RgToStream | 20 |  | [save.c](../save.c) |
| ✅ | SerialDlg | 85 | W | [msg.c](../msg.c) |
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
| ⬜ | **FCheckQueue** | 71 | W | `int16_t FCheckQueue(int16_t, int16_t, uint16_t, uint16_t, uint16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
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

### Unimplemented (6)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **FCheckLayingWP** | 43 | W | `int16_t FCheckLayingWP(uint16_t, int16_t, int16_t, int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckColonizeWP** | 44 | W | `int16_t FCheckColonizeWP(uint16_t, int16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FCheckPatrolWP** | 44 | W | `int16_t FCheckPatrolWP(uint16_t, int16_t, int16_t, uint16_t, uint16_t, uint16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **DumpUniverse** | 74 |  | `void DumpUniverse(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FCheckXferWP** | 90 | W | `int16_t FCheckXferWP(uint16_t, int16_t, int16_t, uint16_t, ITEMACTION *32)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FTutorialEnabledShipBuilder** | 234 | W | `int16_t FTutorialEnabledShipBuilder(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |

### Implemented (20)

<details><summary>Show 20 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CopyStarsFile | 63 |  | [utilgen.c](../utilgen.c) |
| ✅ | FCreateStuff | 269 | W | [init.c](../init.c) |
| ✅ | FSetUpBatchProcessing | 48 |  | [stars.c](../stars.c) |
| ✅ | FWriteTutorialMFile | 90 |  | [log.c](../log.c) |
| ✅ | LogChangeFleet | 173 |  | [log.c](../log.c) |
| ✅ | LogChangePlanet | 129 |  | [log.c](../log.c) |
| ✅ | LogChangeThing | 51 |  | [log.c](../log.c) |
| ✅ | LpReAlloc | 47 |  | [memory.c](../memory.c) |
| ✅ | LpplAlloc | 21 |  | [memory.c](../memory.c) |
| ✅ | ReadIniSettings | 471 | W | [init.c](../init.c) |
| ✅ | ReadRt | 20 |  | [file.c](../file.c) |
| ✅ | WriteBOF | 36 |  | [save.c](../save.c) |
| ✅ | WriteBattlePlan | 41 |  | [save.c](../save.c) |
| ✅ | WriteBattles | 210 |  | [save.c](../save.c) |
| ✅ | WriteOrders | 32 |  | [save.c](../save.c) |
| ✅ | WritePlanet | 161 |  | [save.c](../save.c) |
| ✅ | WritePlayerMessages | 56 |  | [msg.c](../msg.c) |
| ✅ | WriteRtPlr | 58 |  | [save.c](../save.c) |
| ✅ | WriteRtShDef | 65 |  | [save.c](../save.c) |
| ✅ | WriteRtString | 31 |  | [save.c](../save.c) |

</details>

## Depth 10 — Calls up to depth 9

### Unimplemented (2)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **FFinishPlrMsgEntry** | 181 |  | `int16_t FFinishPlrMsgEntry(int16_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **FTutorTaskDone** | 2668 | W | `int16_t FTutorTaskDone(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |

### Implemented (12)

<details><summary>Show 12 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | FCreateFile | 30 |  | [save.c](../save.c) |
| ✅ | FLoadLogFile | 164 |  | [log.c](../log.c) |
| ✅ | FMarkFile | 174 |  | [save.c](../save.c) |
| ✅ | FOpenFile | 173 |  | [file.c](../file.c) |
| ✅ | FReadFleet | 200 |  | [file.c](../file.c) |
| ✅ | FWasRaceFile | 109 |  | [mdi.c](../mdi.c) |
| ✅ | InitInstance | 44 | W | [init.c](../init.c) |
| ✅ | LpflNew | 95 |  | [util.c](../util.c) |
| ✅ | LpplReAlloc | 14 |  | [memory.c](../memory.c) |
| ✅ | LpthNew | 79 |  | [thing.c](../thing.c) |
| ✅ | ReadPlayerMessages | 90 |  | [msg.c](../msg.c) |
| ✅ | WriteFleet | 143 |  | [save.c](../save.c) |

</details>

## Depth 11 — Calls up to depth 10

### Unimplemented (1)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **DropSalvage** | 141 |  | `void DropSalvage(THING *32 *, int32_t *32, int16_t, POINT *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |

### Implemented (13)

<details><summary>Show 13 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | AdvanceTutor | 62 |  | [tutor.c](../tutor.c) |
| ✅ | CreateStartupShip | 73 |  | [create.c](../create.c) |
| ✅ | FAppendFile | 16 |  | [save.c](../save.c) |
| ✅ | FCheckFile | 65 |  | [file.c](../file.c) |
| ✅ | FCheckLogFile | 67 |  | [log.c](../log.c) |
| ✅ | FDupFleet | 53 |  | [util.c](../util.c) |
| ✅ | FDupPlanet | 55 |  | [util.c](../util.c) |
| ✅ | FNewTurnAvail | 30 |  | [file.c](../file.c) |
| ✅ | FSaveRace | 74 | W | [race.c](../race.c) |
| ✅ | FWriteHistFile | 118 |  | [log.c](../log.c) |
| ✅ | FWriteLogFile | 79 |  | [log.c](../log.c) |
| ✅ | LpflNewSplit | 41 |  | [util.c](../util.c) |
| ✅ | MysteryTrader | 99 |  | [turn2.c](../turn2.c) |

</details>

## Depth 12 — Calls up to depth 11

### Unimplemented (8)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **MergeFleetsDlg** | 89 | W | `int16_t MergeFleetsDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **BattleVCR** | 101 | W | `void BattleVCR(int16_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |
| ⬜ | **ScoreXDlg** | 120 | W | `int16_t ScoreXDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **CreateSalvage** | 129 |  | `void CreateSalvage(FLEET *, THING *32 *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **RaceCreationWizard** | 163 | W | `int16_t RaceCreationWizard(uint16_t, int16_t, int16_t)` | [race.c](../race.c) | [race.c](../decompiled/all/race.c) |
| ⬜ | **IDropPart** | 211 | W | `int16_t IDropPart(POINT, HS, int16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **ZipOrderDlg** | 282 | W | `int16_t ZipOrderDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship2.c](../ship2.c) | [ship2.c](../decompiled/all/ship2.c) |
| ⬜ | **ZipProdDlg** | 310 | W | `int16_t ZipProdDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |

### Implemented (12)

<details><summary>Show 12 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | BrowserDlg | 266 | W | [research.c](../research.c) |
| ✅ | CFindTurnsOutstanding | 85 |  | [mdi.c](../mdi.c) |
| ✅ | FDumpCargo | 60 |  | [battle.c](../battle.c) |
| ✅ | FLookupFleet | 70 |  | [util.c](../util.c) |
| ✅ | FLookupPlanet | 91 |  | [util.c](../util.c) |
| ✅ | FLookupThing | 52 |  | [util.c](../util.c) |
| ✅ | LogChangeBtlplan | 15 |  | [log.c](../log.c) |
| ✅ | LogChangeName | 64 |  | [log.c](../log.c) |
| ✅ | LogChangeRelations | 22 |  | [log.c](../log.c) |
| ✅ | LogChangeShDef | 37 |  | [log.c](../log.c) |
| ✅ | PromptSaveGame | 29 | W | [file.c](../file.c) |
| ✅ | RandomEvents | 14 |  | [turn2.c](../turn2.c) |

</details>

## Depth 13 — Calls up to depth 12

### Unimplemented (6)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **HtMineWindow** | 88 | W | `int16_t HtMineWindow(uint16_t, int16_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **RelationsDlg** | 119 | W | `int16_t RelationsDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **InitializeBoard** | 177 |  | `void InitializeBoard(FLEET *32, int16_t, uint16_t, uint8_t *, int16_t *, int16_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **SimpleNewGameDlg** | 223 | W | `int16_t SimpleNewGameDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **FleetTransferCargoBalance** | 337 |  | `void FleetTransferCargoBalance(FLEET *, FLEET *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **BattlePlansDlg** | 439 | W | `int16_t BattlePlansDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |

### Implemented (8)

<details><summary>Show 8 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CTurnsOutSafe | 27 |  | [mdi.c](../mdi.c) |
| ✅ | CalcPlanetMaxPop | 53 |  | [planet.c](../planet.c) |
| ✅ | ChgCargo | 145 |  | [ship.c](../ship.c) |
| ✅ | DestroyCurGame | 130 |  | [file.c](../file.c) |
| ✅ | FEnumCalcJettison | 65 |  | [ship.c](../ship.c) |
| ✅ | FLookupObject | 19 |  | [util.c](../util.c) |
| ✅ | FLookupSelPlanet | 28 |  | [util.c](../util.c) |
| ✅ | FLookupSelShip | 17 |  | [util.c](../util.c) |

</details>

## Depth 14 — Calls up to depth 13

### Unimplemented (4)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **UpdateXferBtns** | 57 | W | `void UpdateXferBtns(void)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **SaveGameState** | 69 | W | `void SaveGameState(void)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **KillShips** | 83 |  | `void KillShips(TOK *32, int16_t, int16_t, FLEET *32, int16_t)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **TransferToOthers** | 142 |  | `void TransferToOthers(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |

### Implemented (9)

<details><summary>Show 9 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | BreedColonistsInTransit | 99 |  | [turn2.c](../turn2.c) |
| ✅ | CMaxFactories | 32 |  | [planet.c](../planet.c) |
| ✅ | CMaxMines | 32 |  | [planet.c](../planet.c) |
| ✅ | ChgPopFromPlanet | 179 |  | [util.c](../util.c) |
| ✅ | FFleetSplitAll | 53 |  | [util.c](../util.c) |
| ✅ | FStargateJump | 233 |  | [ship2.c](../ship2.c) |
| ✅ | FTravelThroughMineFields | 534 |  | [turn.c](../turn.c) |
| ✅ | PctPlanetCapacity | 33 |  | [planet.c](../planet.c) |
| ✅ | XferSupply | 41 |  | [ship.c](../ship.c) |

</details>

## Depth 15 — Calls up to depth 14

### Unimplemented (5)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **FSetupXferBtns** | 131 | W | `int16_t FSetupXferBtns(RECT *)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FTrackXfer** | 147 | W | `int16_t FTrackXfer(uint16_t, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **ThingDecay** | 166 |  | `void ThingDecay(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **PtDisplayPlanetPopInfo** | 247 | W | `POINT PtDisplayPlanetPopInfo(uint16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **InitProduction** | 334 |  | `void InitProduction(PROD *)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |

### Implemented (4)

<details><summary>Show 4 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CMaxOperableDefenses | 37 |  | [planet.c](../planet.c) |
| ✅ | CMaxOperableFactories | 45 |  | [planet.c](../planet.c) |
| ✅ | CMaxOperableMines | 45 |  | [planet.c](../planet.c) |
| ✅ | UpdatePopulations | 77 |  | [turn2.c](../turn2.c) |

</details>

## Depth 16 — Calls up to depth 15

### Unimplemented (3)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **TransferDlg** | 120 | W | `int16_t TransferDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawPopup** | 263 | W | `void DrawPopup(uint16_t, uint16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **Popup** | 295 | W | `void Popup(uint16_t, int16_t, int16_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |

### Implemented (5)

<details><summary>Show 5 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | CBuildProdItem | 389 |  | [turn2.c](../turn2.c) |
| ✅ | CFactoriesOperating | 37 |  | [planet.c](../planet.c) |
| ✅ | CMinesOperating | 44 |  | [planet.c](../planet.c) |
| ✅ | CResourcesAtPlanet | 84 |  | [planet.c](../planet.c) |
| ✅ | CalcPctSurvive | 56 |  | [util.c](../util.c) |

</details>

## Depth 17 — Calls up to depth 16

### Unimplemented (8)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **DrawPlanetMinSum** | 6 | W | `void DrawPlanetMinSum(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **PopupWndProc** | 47 | W | `int32_t PopupWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [popup.c](../popup.c) | [popup.c](../decompiled/all/popup.c) |
| ⬜ | **UpdateGuesses** | 88 |  | `void UpdateGuesses(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |
| ⬜ | **BrowserWndProc** | 138 | W | `int32_t BrowserWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **CalcPlayerScore** | 174 |  | `int32_t CalcPlayerScore(int16_t, SCORE *)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **DrawPlanetStats** | 254 | W | `void DrawPlanetStats(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FTrackSlot** | 311 | W | `int16_t FTrackSlot(uint16_t, int16_t, int16_t, int16_t, int16_t, int16_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **VCRDlg** | 332 | W | `int16_t VCRDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [vcr.c](../vcr.c) | [vcr.c](../decompiled/all/vcr.c) |

### Implemented (3)

<details><summary>Show 3 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | DoBombing | 500 |  | [battle.c](../battle.c) |
| ✅ | DropColonists | 411 |  | [turn2.c](../turn2.c) |
| ✅ | MoveThings | 644 |  | [turn.c](../turn.c) |

</details>

## Depth 18 — Calls up to depth 17

### Unimplemented (2)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **FakeListProc** | 67 | W | `int32_t FakeListProc(uint16_t, uint16_t, uint16_t, int32_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **UpdatePlayerScores** | 250 |  | `void UpdatePlayerScores(void)` | [turn2.c](../turn2.c) | [turn2.c](../decompiled/all/turn2.c) |

## Depth -1 — Cyclic Functions

### Unimplemented (66)

| | Function | Lines | Win | Prototype | Source | Decompiled |
|---|----------|------:|:---:|-----------|--------|------------|
| ⬜ | **DrawPlanetProduction** | 6 | W | `void DrawPlanetProduction(uint16_t, TILE *, OBJ)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **FakeCEProc** | 18 | W | `int32_t FakeCEProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **FakeComboProc** | 18 | W | `int32_t FakeComboProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **SetScanWp** | 22 | W | `int16_t SetScanWp(int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ShipBuilder** | 32 | W | `int16_t ShipBuilder(POINT)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **FinishProduction** | 38 | W | `void FinishProduction(int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **FNearAWayPoint** | 41 | W | `int16_t FNearAWayPoint(POINT, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FFindSomethingAndSelectIt** | 49 | W | `int16_t FFindSomethingAndSelectIt(void)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **FindDlg** | 60 | W | `int16_t FindDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ChangeProduction** | 68 | W | `int16_t ChangeProduction(int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **InitializeProductionDlg** | 70 | W | `void InitializeProductionDlg(uint16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
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
| ⬜ | **ChangeScanSel** | 127 | W | `void ChangeScanSel(SCAN *, int16_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FCanFleetUseStargates** | 131 |  | `int16_t FCanFleetUseStargates(FLEET *32, POINT, POINT)` | [util.c](../util.c) | [util.c](../decompiled/all/util.c) |
| ⬜ | **NewPasswordDlg** | 134 | W | `int16_t NewPasswordDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [utilgen.c](../utilgen.c) | [utilgen.c](../decompiled/all/utilgen.c) |
| ⬜ | **MineWndProc** | 139 | W | `int32_t MineWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **PopupMineralScanChoices** | 143 | W | `void PopupMineralScanChoices(uint16_t, int16_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **InvertPaneBorder** | 144 | W | `POINT InvertPaneBorder(uint16_t, int16_t, POINT, POINT *)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |
| ⬜ | **StartTutor** | 144 | W | `void StartTutor(int16_t)` | [tutor.c](../tutor.c) | [tutor.c](../decompiled/all/tutor.c) |
| ⬜ | **FAddWayPoint** | 151 | W | `int16_t FAddWayPoint(POINT, SCAN *)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **DestroyAllIshdef** | 153 |  | `void DestroyAllIshdef(int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawProductionDlg** | 177 | W | `void DrawProductionDlg(uint16_t, uint16_t, RECT *, int16_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **IWarpBestForWaypoint** | 184 |  | `int16_t IWarpBestForWaypoint(FLEET *32, ORDER *32)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ClickInPlanetOrders** | 201 | W | `uint16_t ClickInPlanetOrders(POINT, int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ProductionDlg** | 208 | W | `int16_t ProductionDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **PlanetClick** | 219 | W | `void PlanetClick(int16_t, int16_t, int16_t, int16_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ExecuteReportClick** | 245 | W | `void ExecuteReportClick(POINT, int16_t, int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **FHandleMeasuringTape** | 247 | W | `int16_t FHandleMeasuringTape(SCAN *, POINT)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FHandleKey** | 254 | W | `int16_t FHandleKey(uint16_t, int16_t, int16_t, uint32_t)` | [stars.c](../stars.c) | [main.c](../decompiled/all/main.c) |
| ⬜ | **TransferStuff** | 263 |  | `int16_t TransferStuff(int16_t, int16_t, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawShipOrders** | 264 | W | `void DrawShipOrders(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **FDamageTok** | 294 |  | `int16_t FDamageTok(TOK *32, int16_t, int32_t *, int32_t, uint16_t, int16_t, int32_t *)` | [battle.c](../battle.c) | [battle.c](../decompiled/all/battle.c) |
| ⬜ | **DumpFleets** | 306 |  | `void DumpFleets(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ExecuteButton** | 309 | W | `void ExecuteButton(int16_t, int16_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **TbWndProc** | 318 | W | `int32_t TbWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [tb.c](../tb.c) | [tb.c](../decompiled/all/tb.c) |
| ⬜ | **DumpPlanets** | 329 |  | `void DumpPlanets(void)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **MineClick** | 375 | W | `void MineClick(int16_t, int16_t, int16_t, int16_t)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **NewGameWizard** | 414 | W | `void NewGameWizard(uint16_t, int16_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **ShipCommandProc** | 462 | W | `void ShipCommandProc(uint16_t, uint16_t, int32_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **NewGameDlg2** | 466 | W | `int16_t NewGameDlg2(uint16_t, uint16_t, uint16_t, int32_t)` | [create.c](../create.c) | [create.c](../decompiled/all/create.c) |
| ⬜ | **ResearchDlg** | 477 | W | `int16_t ResearchDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [research.c](../research.c) | [research.c](../decompiled/all/research.c) |
| ⬜ | **ScannerWndProc** | 490 | W | `int32_t ScannerWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **FHandleWayPointDrag** | 570 | W | `int16_t FHandleWayPointDrag(POINT)` | [scan.c](../scan.c) | [scan.c](../decompiled/all/scan.c) |
| ⬜ | **ClickInShipOrders** | 601 | W | `uint16_t ClickInShipOrders(POINT, int16_t, int16_t, int16_t)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **PlanetWndProc** | 661 | W | `int32_t PlanetWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [planet.c](../planet.c) | [planet.c](../decompiled/all/planet.c) |
| ⬜ | **ProdCommandHandler** | 723 | W | `void ProdCommandHandler(uint16_t, uint16_t, int32_t)` | [produce.c](../produce.c) | [produce.c](../decompiled/all/produce.c) |
| ⬜ | **DrawReportItem** | 764 | W | `void DrawReportItem(uint16_t, RECT *, int16_t, int16_t, int16_t)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **ICompReport** | 800 | W | `int16_t ICompReport(void *, void *)` | [report.c](../report.c) | [report.c](../decompiled/all/report.c) |
| ⬜ | **MessageWndProc** | 811 | W | `int32_t MessageWndProc(uint16_t, uint16_t, uint16_t, int32_t)` | [msg.c](../msg.c) | [msg.c](../decompiled/all/msg.c) |
| ⬜ | **DrawShipWayPtOrders** | 891 | W | `void DrawShipWayPtOrders(uint16_t, TILE *, OBJ)` | [ship.c](../ship.c) | [ship.c](../decompiled/all/ship.c) |
| ⬜ | **DrawMineSurvey** | 997 | W | `void DrawMineSurvey(uint16_t, RECT *)` | [mine.c](../mine.c) | [mine.c](../decompiled/all/mine.c) |
| ⬜ | **SlotDlg** | 1172 | W | `int16_t SlotDlg(uint16_t, uint16_t, uint16_t, int32_t)` | [build.c](../build.c) | [build.c](../decompiled/all/build.c) |
| ⬜ | **CommandHandler** | 1185 | W | `void CommandHandler(uint16_t, uint16_t)` | [mdi.c](../mdi.c) | [mdi.c](../decompiled/all/mdi.c) |

### Implemented (41)

<details><summary>Show 41 implemented functions</summary>

| | Function | Lines | Win | Source |
|---|----------|------:|:---:|--------|
| ✅ | BringUpHostDlg | 174 | W | [mdi.c](../mdi.c) |
| ✅ | ChangeMainObjSel | 127 | W | [planet.c](../planet.c) |
| ✅ | CreateTutorWorld | 74 |  | [create.c](../create.c) |
| ✅ | DestroyAllIshdefSB | 27 |  | [ship.c](../ship.c) |
| ✅ | DoBattles | 58 |  | [battle.c](../battle.c) |
| ✅ | DoOrders | 54 |  | [turn.c](../turn.c) |
| ✅ | DoThingInteractions | 516 |  | [thing.c](../thing.c) |
| ✅ | EnsureAis | 60 |  | [mdi.c](../mdi.c) |
| ✅ | EstMineralsMined | 231 |  | [mine.c](../mine.c) |
| ✅ | EstimateItemProdSched | 194 |  | [produce.c](../produce.c) |
| ✅ | FAttack | 708 |  | [battle.c](../battle.c) |
| ✅ | FBuildObject | 522 |  | [turn2.c](../turn2.c) |
| ✅ | FDoCoolBattle | 350 |  | [battle.c](../battle.c) |
| ✅ | FFindNearestObject | 228 |  | [util.c](../util.c) |
| ✅ | FGenerateTurn | 632 |  | [turn.c](../turn.c) |
| ✅ | FLoadGame | 1215 |  | [file.c](../file.c) |
| ✅ | FOpenGame | 215 | W | [mdi.c](../mdi.c) |
| ✅ | FRunLogFile | 34 |  | [log.c](../log.c) |
| ✅ | FRunLogRecord | 822 |  | [log.c](../log.c) |
| ✅ | FWriteDataFile | 498 |  | [save.c](../save.c) |
| ✅ | FillPlanetProdLB | 133 | W | [planet.c](../planet.c) |
| ✅ | FleetOrdersChangeTarget | 68 |  | [ship.c](../ship.c) |
| ✅ | FrameWndProc | 665 | W | [mdi.c](../mdi.c) |
| ✅ | GenNewGameFromFile | 480 |  | [create.c](../create.c) |
| ✅ | GenerateWorld | 1557 |  | [create.c](../create.c) |
| ✅ | HostModeDialog | 305 | W | [mdi.c](../mdi.c) |
| ✅ | HostTimerProc | 177 | W | [mdi.c](../mdi.c) |
| ✅ | KillQueuedMassPackets | 64 |  | [build.c](../build.c) |
| ✅ | KillQueuedShips | 69 |  | [build.c](../build.c) |
| ✅ | Merge2Fleets | 50 |  | [ship.c](../ship.c) |
| ✅ | MineMinerals | 21 |  | [turn2.c](../turn2.c) |
| ✅ | MoveFleets | 845 |  | [turn.c](../turn.c) |
| ✅ | Produce | 384 |  | [turn2.c](../turn2.c) |
| ✅ | ProjectedResearchSpending | 48 |  | [research.c](../research.c) |
| ✅ | PszProductionETA | 69 |  | [planet.c](../planet.c) |
| ✅ | RemoveIshdefFromAllQueues | 68 |  | [ship.c](../ship.c) |
| ✅ | ReportWndProc | 354 | W | [report.c](../report.c) |
| ✅ | SatisfyOrders | 1682 |  | [turn3.c](../turn3.c) |
| ✅ | TitleWndProc | 336 | W | [mdi.c](../mdi.c) |
| ✅ | UpdateResearchStatus | 305 |  | [turn2.c](../turn2.c) |
| ✅ | WinMain | 338 |  | [winmain.c](../winmain.c) |

</details>

