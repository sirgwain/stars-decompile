#include <stdio.h>
#include <string.h>
#include "types.h"
#include "strings.h"

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("stars CLI\n");

    printf("PszGetCompressedString(0): %s\n", PszGetCompressedString(0));

    return 0;
}
