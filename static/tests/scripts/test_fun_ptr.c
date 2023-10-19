#include <stdio.h>
#include <stdlib.h>

int main (void)
{
    int (*fctPtr)(const char *);

    fctPtr = &puts;

    (*fctPtr)("coucc");

    return EXIT_SUCCESS;
}
