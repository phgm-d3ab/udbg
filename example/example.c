#include "../udbg.h"

#include <stdlib.h>

void crash()
{
    int *ptr = NULL;
    *ptr = 1;
}

int main()
{
    udbg_init(NULL, UDBG_TIME, FOO | BAZ);

    udbg_log(FOO, "these messages only appear in debug configuration");
    udbg_log(BAR, "channel for this message is disabled so it never appears");
    udbg_log(BAZ, "baz");

    unsigned int x = 0xdeadbeef;
    udbg_hexdump(FOO, &x, sizeof(unsigned int));

    // lets have a crash
    crash();
}