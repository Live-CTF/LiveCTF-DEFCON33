#include <stdio.h>
#include <stdlib.h>

int checker(unsigned char *input) {
    int result = 1;
    result &= input[3] + input[4] == 0x41+0x43;

    return result;
}
