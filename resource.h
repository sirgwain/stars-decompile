#pragma once

// ---------------- Icons (100–119) ----------------
#define IDI_STARS 100
#define IDI_WAIT  101
#define IDI_HOST  102
#define IDI_BANG1 110
#define IDI_BANG2 111
#define IDI_BANG3 112
#define IDI_TORP1 120
#define IDI_TORP2 121
#define IDI_TORP3 122
#define IDI_TORP4 123

// ---------------- Cursors (200–249) --------------
#define IDC_SCANNER          200
#define IDC_SCANNER_ADD      201
#define IDC_OPEN_GRAB        202
#define IDC_CLOSE_GRAB       203
#define IDC_TRASH            204
#define IDC_INVALID          205
#define IDC_HSPLIT           206 // horizontalsplit.cur
#define IDC_VSPLIT           207 // veriticalsplit.cur (typo in file name ok)
#define IDC_MOVEARROWS       208 // move-arrows.cur
#define IDC_TOOLTIP_QUESTION 209
#define IDC_HAND_CUSTOM      210 // pointerhand.cur

// ---------------- Bitmaps (300–399) --------------
#define IDB_TOOLBAR              300 // toolbar.bmp
#define IDB_SCANNER              301 // scanner.bmp (as HBITMAP)
#define IDB_UNKNOWNPLANET        302 // unknownplanet.bmp
#define IDB_FONT_DIGITS          303 // fontdigits.bmp
#define IDB_SCREEN50             304 // screen50.bmp
#define IDB_CARGO                305 // cargo.bmp
#define IDB_DOCK                 306 // dockbmp.bmp
#define IDB_EMPTY_HULL_SLOT      307 // emptyhullsloticons.bmp
#define IDB_MSGFILTER_CHECKBOX   308 // messageicons.bmp (checkbox sheet you mentioned)
#define IDB_FILTER_CHECKBOX_MONO 309 // monochromeicons.bmp

// Mines pattern tiles - scannerminespattern1/2/3.bmp
#define IDB_MINESPAT_BASE 460
#define IDB_MINESPAT_1    460
#define IDB_MINESPAT_2    461
#define IDB_MINESPAT_3    462

// ---------------- DIB sheets as RCDATA (400–599) -----
// These are accessed by your LoadDIBResourceToGlobal()
#define IDDIB_PLANET_ICONS    400 // planeticons.bmp
#define IDDIB_THING_ICONS     401 // thingicons.bmp
#define IDDIB_SCANNER_TOOLBAR 402 // scannerfleets.bmp (scanner toolbar sheet)

// Hull icon sheets (large) - hullicons1..5.bmp
#define IDDIB_HULL_ICONS_BASE 410
#define IDDIB_HULL_ICONS_1    410
#define IDDIB_HULL_ICONS_2    411
#define IDDIB_HULL_ICONS_3    412
#define IDDIB_HULL_ICONS_4    413
#define IDDIB_HULL_ICONS_5    414

// Hull icon sheets (small) - hulliconssmall1..5.bmp
#define IDDIB_HULL_ICONS_SMALL_BASE 420
#define IDDIB_HULL_ICONS_SMALL_1    420
#define IDDIB_HULL_ICONS_SMALL_2    421
#define IDDIB_HULL_ICONS_SMALL_3    422
#define IDDIB_HULL_ICONS_SMALL_4    423
#define IDDIB_HULL_ICONS_SMALL_5    424

// Tech icons - techicons1..7.bmp
#define IDDIB_TECH_ICONS_BASE 430
#define IDDIB_TECH_ICONS_1    430
#define IDDIB_TECH_ICONS_2    431
#define IDDIB_TECH_ICONS_3    432
#define IDDIB_TECH_ICONS_4    433
#define IDDIB_TECH_ICONS_5    434
#define IDDIB_TECH_ICONS_6    435
#define IDDIB_TECH_ICONS_7    436

// Player icon sheets
#define IDDIB_PLAYER_ICONS       440 // playericons.bmp
#define IDDIB_PLAYER_ICONS_SMALL 441 // playeroconssmall.bmp  (filename as listed)
#define IDDIB_PLAYER_ICONS_TINY  442 // playericonstiny.bmp

#define IDDIB_NUM_DESIGNS_PLATE 450 // numdesignsplate.bmp

/* Title splash (original Stars! used resource id 0x01C1). */
#define IDDIB_SPLASH 0x01C1 // splash.bmp

// ---------------- Accelerators (keep legacy IDs) ----
#define IDA_MAIN  116
#define IDA_TITLE 1080

// ---------------- Menu IDs (700-799) ----------------
#define STARSMENU 700

// File menu
#define IDM_FILE_NEW         701
#define IDM_RACE_WIZARD      702
#define IDM_FILE_OPEN        703
#define IDM_FILE_CLOSE       704
#define IDM_FILE_SAVE        705
#define IDM_FILE_SAVE_SUBMIT 706
#define IDM_FILE_PRINT_MAP   707
#define IDM_FILE_EXIT        708

// View menu
#define IDM_VIEW_TOOLBAR       710
#define IDM_VIEW_FIND          711
#define IDM_VIEW_ZOOM_25       712
#define IDM_VIEW_ZOOM_38       713
#define IDM_VIEW_ZOOM_50       714
#define IDM_VIEW_ZOOM_75       715
#define IDM_VIEW_ZOOM_100      716
#define IDM_VIEW_ZOOM_125      717
#define IDM_VIEW_ZOOM_150      718
#define IDM_VIEW_ZOOM_200      719
#define IDM_VIEW_ZOOM_400      720
#define IDM_VIEW_LAYOUT_LARGE  721
#define IDM_VIEW_LAYOUT_MEDIUM 722
#define IDM_VIEW_LAYOUT_SMALL  723
#define IDM_VIEW_PLAYER_COLORS 724
#define IDM_VIEW_RACE          725
#define IDM_VIEW_GAME_PARAMS   726

// Turn menu
#define IDM_TURN_WAIT_NEW 730
#define IDM_TURN_GENERATE 731

// Commands menu
#define IDM_CMD_SHIP_DESIGN     740
#define IDM_CMD_RESEARCH        741
#define IDM_CMD_BATTLE_PLANS    742
#define IDM_CMD_RELATIONS       743
#define IDM_CMD_CHANGE_PASSWORD 744

// Report menu
#define IDM_RPT_PLANETS       750
#define IDM_RPT_FLEETS        751
#define IDM_RPT_OTHERS_FLEETS 752
#define IDM_RPT_BATTLES       753
#define IDM_RPT_SCORE         754
#define IDM_RPT_DUMP_UNIVERSE 755
#define IDM_RPT_DUMP_PLANETS  756
#define IDM_RPT_DUMP_FLEETS   757

// Help menu
#define IDM_HELP_INTRO         760
#define IDM_HELP_PLAYERS_GUIDE 761
#define IDM_HELP_TECH_BROWSER  762
#define IDM_HELP_TUTORIAL      763
#define IDM_HELP_ABOUT         764

// ---------------------------------------------------------------------
// Original Stars! (Win16) WM_COMMAND IDs inferred from CommandHandler()
//
// These are the legacy command IDs observed in the Win16 decompile.
// They intentionally do NOT reuse the modern (700+) IDs above, so there
// are no collisions. Use these when translating CommandHandler/FrameWndProc
// logic that still keys off the original values.
//
// Naming convention here: IDM_* for legacy (Win16) command IDs.

// ---- Debug / developer commands --------------------------------------
#define IDM_DEBUG_DUMP_FLEETS   0x0053 // DumpFleets()
#define IDM_DEBUG_DUMP_PLANETS  0x0054 // DumpPlanets()
#define IDM_DEBUG_DUMP_UNIVERSE 0x0055 // DumpUniverse()

// ---- About / score dialogs -------------------------------------------
#define IDM_GAME_SCORE  0x005F // Score dialog (one entry point)
#define IDM_GAME_SCORE2 0x0060 // Score dialog (alternate entry point)
#define IDM_HELP_ABOUT  0x0063 // About dialog

// ---- Fleet waypoint editing ------------------------------------------
#define IDM_FLEET_DELETE_WAYPOINT 0x0067 // Delete current waypoint (confirm)
#define IDM_FLEET_INSERT_WAYPOINT 0x0068 // Waypoint insert/delete sibling command

// ---- File / game lifecycle -------------------------------------------
#define IDM_FILE_HOST_GAME       0x0069
#define IDM_FILE_OPEN_GAME       0x006D // Open game
#define IDM_FILE_NEW_GAME        0x006E // New game wizard
#define IDM_FILE_RETURN_TO_TITLE 0x0071 // Close game, return to title screen

// Toolbar/accelerator aliases that jump to the same paths
#define IDM_TOOL_NEW_GAME  0x0ED8 // Alias: New game
#define IDM_TOOL_OPEN_GAME 0x0ED9 // Alias: Open game

// ---- Commands (ship design / research / diplomacy) --------------------
#define IDM_GAME_SHIP_BUILDER 0x007D // ShipBuilder
#define IDM_GAME_RESEARCH     0x007E // Research dialog

// Diplomacy / battle plans / turn control cluster
#define IDM_GAME_RELATIONS     0x07D9 // Relations dialog
#define IDM_GAME_WAIT_FOR_TURN 0x07DA // Wait-for-turn dialog/command
#define IDM_GAME_BATTLE_PLANS1 0x07DB // Battle plans dialog
#define IDM_GAME_BATTLE_PLANS2 0x07DC // Battle plans dialog (alias)
#define IDM_GAME_RELATIONS2    0x07DE // Relations dialog (alias)

// ---- View / window layout --------------------------------------------
#define IDM_VIEW_LAYOUT_0 0x0082 // Window layout 0
#define IDM_VIEW_LAYOUT_1 0x0083 // Window layout 1
#define IDM_VIEW_LAYOUT_2 0x0084 // Window layout 2 ("small" layout)

// Browser toggle (menu vs alias ID)
#define IDM_VIEW_BROWSER_TOGGLE  0x0088 // Toggle tech browser window
#define IDM_VIEW_BROWSER_TOGGLE2 0x0100 // Alias: browser toggle

// Help index (menu vs alias ID)
#define IDM_HELP_CONTENTS  0x008A // Help index/contents
#define IDM_HELP_CONTENTS2 0x0101 // Alias: help index/contents

// ---- Race wizards -----------------------------------------------------
#define IDM_RACE_CREATE 0x0081 // Race creation wizard (default players)
#define IDM_RACE_EDIT1  0x009C // Race edit wizard (existing player)
#define IDM_RACE_EDIT2  0x009D // Race edit wizard (alias)

// ---- Reports ----------------------------------------------------------
#define IDM_REPORT_PLANET      0x08FD // Planet report
#define IDM_REPORT_CYCLE       0x08FE // Cycle report type
#define IDM_REPORT_FLEET       0x08FF // Fleet report
#define IDM_REPORT_ENEMY_FLEET 0x0900 // Enemy fleets report
#define IDM_REPORT_BATTLE      0x0901 // Battles report

// ---- MRU (Most Recently Used) slots ----------------------------------
#define IDM_FILE_MRU1 0x10CC // MRU slot 1
#define IDM_FILE_MRU2 0x10CD // MRU slot 2
#define IDM_FILE_MRU3 0x10CE // MRU slot 3
#define IDM_FILE_MRU4 0x10CF // MRU slot 4
#define IDM_FILE_MRU5 0x10D0 // MRU slot 5
#define IDM_FILE_MRU6 0x10D1 // MRU slot 6
#define IDM_FILE_MRU7 0x10D2 // MRU slot 7
#define IDM_FILE_MRU8 0x10D3 // MRU slot 8
#define IDM_FILE_MRU9 0x10D4 // MRU slot 9

// ---- Scanner zoom factors (radio group) -------------------------------
#define IDM_SCAN_ZOOM_0 0x0F3D // scanner zoom (entry 0)
#define IDM_SCAN_ZOOM_1 0x0F3E // scanner zoom (entry 1)
#define IDM_SCAN_ZOOM_2 0x0F3F // scanner zoom (entry 2)
#define IDM_SCAN_ZOOM_3 0x0F40 // scanner zoom (entry 3)
#define IDM_SCAN_ZOOM_4 0x0F41 // scanner zoom (entry 4) (baseline in code)
#define IDM_SCAN_ZOOM_5 0x0F42 // scanner zoom (entry 5)
#define IDM_SCAN_ZOOM_6 0x0F43 // scanner zoom (entry 6)
#define IDM_SCAN_ZOOM_7 0x0F44 // scanner zoom (entry 7)
#define IDM_SCAN_ZOOM_8 0x0F45 // scanner zoom (entry 8)

// ---- Turn ending / host/generate variants ------------------------------
#define IDM_TURN_END_A 0x0EDA // end turn variant A
#define IDM_TURN_END_B 0x0EDB // end turn variant B (toggles an internal bit)

// ---- Dynamic popup range ----------------------------------------------
#define IDM_POPUP_BASE 15000 // Dynamic popup items start here (inferred)

// ---- Debug: force-generate turns (decompiler had type confusion) -------
#define IDM_DEBUG_GEN_10_TURNS   21000 // generate 10 turns (inferred)
#define IDM_DEBUG_GEN_100_TURNS  21001 // generate 100 turns (0x5209)
#define IDM_DEBUG_GEN_1000_TURNS 21002 // generate 1000 turns (likely; decompile mis-typed)

/* CommandHandler-only menu IDs (names TBD) */
#define IDM_UNKNOWN_098D 0x098D
#define IDM_UNKNOWN_09C1 0x09C1
#define IDM_UNKNOWN_09C2 0x09C2
#define IDM_UNKNOWN_09C4 0x09C4
#define IDM_UNKNOWN_09C5 0x09C5
#define IDM_UNKNOWN_0EE2 0x0EE2
#define IDM_UNKNOWN_0FA1 0x0FA1
#define IDM_UNKNOWN_1068 0x1068
#define IDM_UNKNOWN_1069 0x1069

// ---------------- Dialog IDs (800-899) --------------
#define IDD_ABOUTBOX  800
#define IDC_VERSION   801
#define IDC_CREDITS   802
#define IDC_ORDERINFO 803

#define IDD_BROWSER         128
#define IDD_PASSWORD        140
#define IDD_SIMPLE_NEW_GAME 209

// ---------------- Tutorial blocks (RCDATA) ----------
#define IDR_TUTORIAL_HST 10001 // res/tutorial/10001-tutorail.hst
#define IDR_TUTORIAL_M1  10003 // res/tutorial/10003-tutorail.m1
#define IDR_TUTORIAL_M2  10005 // res/tutorial/10005-tutorail.m2

// ---------------- Custom Stars Messages ----------

#define WM_STARS_STARTUP  0x464
#define WM_STARS_HOST     0x465
#define WM_STARS_CONTINUE 0x466

// ---------------- Auto generated, could be dupes ----------

#define IDC_HELP                  118
#define IDC_IMMUNE_TO_TEMPERATURE 292
#define IDC_IMMUNE_TO_RADIATION   293
#define IDC_RENAME                1051
#define IDC_SAVE                  1065
#define IDC_NO_DON_T_SAVE         1067
#define IDC_NEXT                  1071
#define IDC_FINISH                1072
#define IDC_DELETE                2071

#define IDC_IMPORT 2070
#define IDC_EDIT   2072

#define IDC_PREV  2064
#define IDC_NEXT  2065
#define IDC_FIRST 2066
#define IDC_LAST  2067
#define IDC_UP    2068
#define IDC_DOWN  2069

#define IDC_SHIPLIST 1035

#define IDC_U16_0x0051 0x0051 /* 81 */
#define IDC_U16_0x008B 0x008B /* 139 */
#define IDC_U16_0x00A1 0x00A1 /* 161 */
#define IDC_U16_0x00A3 0x00A3 /* 163 */
#define IDC_U16_0x00C6 0x00C6 /* 198 */
#define IDC_U16_0x00CB 0x00CB /* 203 */
#define IDC_U16_0x00D3 0x00D3 /* 211 */

#define IDC_U16_0x010B 0x010B /* 267 */
#define IDC_U16_0x010C 0x010C /* 268 */
#define IDC_U16_0x010D 0x010D /* 269 */
#define IDC_U16_0x010F 0x010F /* 271 */
#define IDC_U16_0x0116 0x0116 /* 278 */
#define IDC_U16_0x0118 0x0118 /* 280 */
#define IDC_U16_0x0123 0x0123 /* 291 */
#define IDC_U16_0x0130 0x0130 /* 304 */

#define IDC_U16_0x0406 0x0406 /* 1030 */
#define IDC_U16_0x0416 0x0416 /* 1046 */
#define IDC_U16_0x0417 0x0417 /* 1047 */
#define IDC_U16_0x041A 0x041A /* 1050 */
#define IDC_U16_0x041D 0x041D /* 1053 */
#define IDC_U16_0x041E 0x041E /* 1054 */
#define IDC_U16_0x041F 0x041F /* 1055 */
#define IDC_U16_0x0420 0x0420 /* 1056 */
#define IDC_U16_0x0421 0x0421 /* 1057 */
#define IDC_U16_0x0422 0x0422 /* 1058 */
#define IDC_U16_0x042E 0x042E /* 1070 */

#define IDC_U16_0x0434 0x0434 /* 1076 */

#define IDC_U16_0x07D3 0x07D3 /* 2003 */
#define IDC_U16_0x07D5 0x07D5 /* 2005 */
#define IDC_U16_0x07D6 0x07D6 /* 2006 */

#define IDC_U16_0x07DF 0x07DF /* 2015 */
#define IDC_U16_0x07E0 0x07E0 /* 2016 */
#define IDC_U16_0x07E1 0x07E1 /* 2017 */
#define IDC_U16_0x07E2 0x07E2 /* 2018 */

#define IDC_U16_0x080C 0x080C /* 2060 */