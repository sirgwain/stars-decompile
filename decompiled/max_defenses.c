/**
 * max_defenses.c - Stars! Maximum Defense Calculations (Raw Decompiled)
 *
 * Extracted from stars.exe 2.60j RC3 using Ghidra decompilation
 * This is the raw Ghidra output with original function/variable names
 *
 * Source: all_funcs.c lines 26540-26559 (CMaxDefenses)
 *                         26571-26608 (CMaxOperableDefenses)
 */

#include "max_defenses.h"

/* ============================================================================
 * FUN_1048_5714 - CMaxDefenses
 * Address: 1048:5714
 * Source: all_funcs.c:26540-26559
 *
 * Calculates the absolute maximum defenses a planet can support based on
 * habitability percentage.
 * ============================================================================ */

int __cdecl16far FUN_1048_5714(undefined2 param_1, undefined2 param_2, int param_3)
{
    int iVar1;
    int local_6;

    /* Get planet habitability percentage */
    local_6 = FUN_1048_5080(param_1, param_2, param_3);  /* PctPlanetDesirability */

    /* Multiply by 4 to get max defenses */
    local_6 = local_6 * 4;

    /* Clamp to minimum of 10 */
    if (local_6 < 10) {
        local_6 = 10;
    }

    /* Clamp to maximum of 100 */
    if (100 < local_6) {
        local_6 = 100;
    }

    /* Check if player is Alternate Reality race */
    iVar1 = FUN_10e0_253a((int)&c_common::vtickTooltip1stVis + param_3 * 0xc0, 0xe);
    if (iVar1 == 8) {  /* PRT_ALTERNATE_REALITY */
        local_6 = 0;
    }

    return local_6;
}


/* ============================================================================
 * FUN_1048_5768 - CMaxOperableDefenses
 * Address: 1048:5768
 * Source: all_funcs.c:26571-26608
 *
 * Calculates the maximum operable defenses based on both habitability limit
 * and population capacity.
 * ============================================================================ */

int __cdecl16far FUN_1048_5768(undefined4 param_1, int param_3, int param_4)
{
    int iVar1;
    uint uVar2;
    int iVar3;
    bool bVar4;
    long lVar5;
    uint local_c;
    int local_a;
    int local_8;
    int local_4;

    /* Get CMaxDefenses (habitability-based limit) */
    iVar1 = FUN_1048_5714((int)param_1, param_1._2_2_, param_3);  /* CMaxDefenses */

    /* Get current population (32-bit value at planet+0x28) */
    local_c = *(uint *)((int)param_1 + 0x28);   /* population low word */
    local_a = *(int *)((int)param_1 + 0x2a);    /* population high word */

    /* If fNextYear flag set, add projected population growth */
    if (param_4 != 0) {  /* fNextYear */
        iVar3 = local_a;
        /* Get population change for next turn */
        uVar2 = FUN_1038_4b42((int)param_1, param_1._2_2_, 0);  /* ChgPopFromPlanet */
        /* Add to current population (32-bit addition with carry) */
        bVar4 = CARRY2(local_c, uVar2);
        local_c = local_c + uVar2;
        local_a = local_a + iVar3 + (uint)bVar4;
    }

    /* Calculate (population + 24) / 25 */
    /* 0x18 = 24, 0x19 = 25 */
    lVar5 = FUN_1118_0c28(local_c + 0x18, local_a + (uint)(0xffe7 < local_c), 0x19, 0);
    local_8 = (int)lVar5;

    /* Cap at 1000 */
    if (1000 < lVar5) {
        local_8 = 1000;
    }

    /* Take minimum of population limit and CMaxDefenses */
    local_4 = local_8;
    if (iVar1 < local_8) {
        local_4 = iVar1;
    }

    /* Check if player is Alternate Reality race */
    iVar1 = FUN_10e0_253a((int)&c_common::vtickTooltip1stVis + param_3 * 0xc0, 0xe);
    if (iVar1 == 8) {  /* PRT_ALTERNATE_REALITY */
        local_4 = 0;
    }

    return local_4;
}


/* ============================================================================
 * REFERENCED FUNCTIONS (stubs - actual implementations elsewhere)
 * ============================================================================ */

/*
 * FUN_1048_5080 - PctPlanetDesirability
 * Address: 1048:5080
 * Returns habitability percentage for a planet (0-100 for habitable)
 */

/*
 * FUN_1038_4b42 - ChgPopFromPlanet
 * Address: 1038:4b42
 * Returns population change for next turn
 */

/*
 * FUN_10e0_253a - GetPlayerField
 * Address: 10e0:253a
 * Gets a field from player structure (offset 0x0e = PRT)
 */

/*
 * FUN_1118_0c28 - DivLong
 * Address: 1118:0c28
 * 32-bit division helper function
 */
