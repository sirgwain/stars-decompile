
#include "types.h"

#include "globals.h"
#include "thing.h"

/* functions */
int16_t IdmGiveTraderPart(uint16_t grbitTrader, int16_t iplr, uint16_t *piGoto) {
    uint16_t iGoto;
    int16_t  idm;

    /* TODO: implement */
    return 0;
}

void DrawThingGauge(uint16_t hdc, RECT *prc, THING *lpth, int16_t md) {
    int16_t  iMode;
    int16_t  cSections;
    int16_t  fDisabled;
    uint16_t rghbr[5];
    int16_t  c;
    int16_t  i;
    int32_t  rgSize[5];
    int32_t  lMax;
    int32_t  l;

    /* TODO: implement */
}

void FreeLpth(THING *lpth) {
    THING *end;
    size_t idx;

    end = lpThings + cThing;
    if (lpth < end - 1) {
        idx = (size_t)(lpth - lpThings);
        memmove(lpth, lpth + 1, (size_t)(cThing - (int32_t)idx - 1) * sizeof(*lpth));
    }
    cThing = (int16_t)(cThing - 1);
}

int16_t CPlanetsInCircle(POINT pt, int32_t r2) {
    int16_t xStart;
    POINT  *ppt;
    int16_t yEnd;
    int16_t dy;
    POINT  *pptEnd;
    int16_t yStart;
    int16_t i;
    int16_t r;
    int16_t cPl;
    int16_t dx;
    int16_t xEnd;

    /* TODO: implement */
    return 0;
}

int16_t PctWormholeMoves(THING *lpth) {
    int16_t pct;

    pct = (int16_t)((int16_t)(lpth->thw.cLastMove / 5) - (int16_t)(2 - lpth->thw.iStable));

    if (pct < 0) {
        pct = 0;
    } else if (pct > 6) {
        pct = 6;
    }

    return pct;
}

void DoThingInteractions(int16_t fPostMove) {
    int32_t  wtThreshhold;
    uint16_t grbitPlrTrader;
    int16_t  iplr;
    int32_t  wtMin;
    POINT    pt;
    int16_t  iplrSav;
    uint8_t  rgTech[6];
    int32_t  wtNext;
    int32_t  dy;
    THING   *lpthMac;
    PLANET  *lpplMac;
    PLANET  *lppl;
    int16_t  i;
    int16_t  ifl;
    FLEET   *lpfl;
    THING   *lpth;
    int16_t  idm;
    int16_t  cPlrTrueMaxTech;
    int32_t  dx;
    int16_t  fMaxTech;
    int32_t  l;
    int16_t  iGoto;
    uint16_t grbitTrader;
    int16_t  iLvl;
    int32_t  cTech;
    int16_t  cTry;
    int16_t  iPass;
    int16_t  iLowest;
    int16_t  cTechCur;
    int16_t  iOffset;
    int16_t  ish;
    int32_t  lSpent;
    SHDEF    shdef;
    SHDEF   *lpshdefDest;
    FLEET   *lpflNew;
    int16_t  cGive;

    /* debug symbols */
    /* block (block) @ MEMORY_THING:0x0e63 */
    /* block (block) @ MEMORY_THING:0x0fca */
    /* block (block) @ MEMORY_THING:0x1180 */
    /* block (block) @ MEMORY_THING:0x1229 */
    /* block (block) @ MEMORY_THING:0x1359 */
    /* block (block) @ MEMORY_THING:0x1829 */
    /* block (block) @ MEMORY_THING:0x1961 */
    /* block (block) @ MEMORY_THING:0x19d2 */
    /* label LNoLifeboat @ MEMORY_THING:0x1324 */
    /* label LGivePart @ MEMORY_THING:0x1180 */
    /* label LGiveITech @ MEMORY_THING:0x1090 */
    /* label LAutoTech @ MEMORY_THING:0x1961 */
    /* label LChgMin @ MEMORY_THING:0x1896 */

    /* TODO: implement */
}

THING *LpthNew(int16_t iplr, ThingType ith) {
    int16_t iItem;
    int16_t i;
    THING  *lpth;
    THING   thNew;

    /* TODO: implement */
    return NULL;
}

int16_t IValidateWormholePos(THING *lpthWorm) {
    int16_t iRet;
    int32_t dy;
    THING  *lpthMac;
    FLEET  *lpfl;
    int16_t ifl;
    int16_t i;
    THING  *lpth;
    int16_t dUni;
    int32_t dx;
    int32_t l;
    int16_t x, y;

    iRet = 0;
    dUni = game.mdSize * 400;
    x = lpthWorm->pt.x;
    y = lpthWorm->pt.y;

    if (x < 1000 || y < 1000) {
        iRet = 0xf;
    } else if (dUni + 1400 < x || dUni + 1400 < y) {
        iRet = 0xf;
    } else {
        FORTHINGS(lpth, lpthMac) {
            if (x == lpth->pt.x && y == lpth->pt.y && lpthWorm != lpth) {
                return 0xf;
            }
        }

        for (i = 0; i < game.cPlanMax; i++) {
            if (x == rgptPlan[i].x && y == rgptPlan[i].y) {
                return 0xf;
            }
        }

        FORFLEETS(lpfl, ifl) {
            if (x == lpfl->pt.x && y == lpfl->pt.y) {
                return 0xf;
            }
        }

        if (x < 1010 || y < 1010 || dUni + 1390 < x || dUni + 1390 < y) {
            iRet = 4;
        }

        FORTHINGS(lpth, lpthMac) {
            if (lpth->ith == ithWormhole && lpthWorm != lpth) {
                dx = x - lpth->pt.x;
                dy = y - lpth->pt.y;
                l = dx * dx + dy * dy;

                if (lpth->idFull == lpthWorm->thw.idPartner) {
                    if (l < 70 * 70) {
                        if (l < 5 * 5) {
                            iRet = iRet | 8;
                        } else if (l < 10 * 10) {
                            iRet = iRet | 4;
                        } else if (l < 30 * 30) {
                            iRet = iRet | 2;
                        } else {
                            iRet = iRet | 1;
                        }
                    }
                } else if (l < 30 * 30) {
                    if (l < 4 * 4) {
                        iRet = iRet | 8;
                    } else if (l < 8 * 8) {
                        iRet = iRet | 4;
                    } else if (l < 15 * 15) {
                        iRet = iRet | 2;
                    } else {
                        iRet = iRet | 1;
                    }
                }
            }
        }

        for (i = 0; i < game.cPlanMax; i++) {
            dx = x - rgptPlan[i].x;
            dy = y - rgptPlan[i].y;
            l = dx * dx + dy * dy;

            if (l < 28 * 28) {
                if (l < 5 * 5) {
                    iRet = iRet | 8;
                } else if (l < 10 * 10) {
                    iRet = iRet | 4;
                } else if (l < 20 * 20) {
                    iRet = iRet | 2;
                } else {
                    iRet = iRet | 1;
                }
            }
        }
    }

    return iRet;
}
