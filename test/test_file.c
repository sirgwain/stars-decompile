#include "acutest.h"

#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "types.h"
#include "file.h"   /* FLoadGame */

/* Snapshot/restore just the globals this test mutates. */
typedef struct SaveGlobalsSnapshot
{
    char szBase[sizeof(szBase)];
    char szWork[sizeof(szWork)];
} SaveGlobalsSnapshot;

static SaveGlobalsSnapshot snapshot_globals(void)
{
    SaveGlobalsSnapshot s;
    memcpy(s.szBase, szBase, sizeof(szBase));
    memcpy(s.szWork, szWork, sizeof(szWork));
    return s;
}

static void restore_globals(const SaveGlobalsSnapshot *s)
{
    memcpy(szBase, s->szBase, sizeof(szBase));
    memcpy(szWork, s->szWork, sizeof(szWork));
}

static void set_base(const char *base)
{
    /* Ensure deterministic contents, then copy. */
    memset(szBase, 0, sizeof(szBase));
    memset(szWork, 0, sizeof(szWork));
    strncpy(szBase, base, sizeof(szBase) - 1);
}


TEST_LIST = {
    {NULL, NULL}
};
