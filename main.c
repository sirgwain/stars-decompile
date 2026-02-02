#include <stdio.h>
#include <string.h>
#include "cli.h"
#include "init.h"

int main(int argc, char **argv) {
    // call LpAlloc to setup memory blocks
    FAllocStuff();

    int rc = StarsCli_Run(argc, argv);

    // free stuff we allocated
    DeallocStuff();

    return rc;
}
