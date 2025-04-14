
#include <stdio.h>
#include <stdlib.h>

int checker(char *input) {
    int result = 1;

// password = "PpBOW2quokEiO2to"
result &= ((input[5] + input[13]) & 0xFFFF) == 100;
result &= ((input[13] + input[2]) & 0xFFFF) == 116;
result &= ((input[2] + input[8]) & 0xFFFF) == 177;
result &= ((input[8] ^ input[3]) & 0xFFFF) == 32;
result &= ((input[3] + input[4]) & 0xFFFF) == 166;
result &= ((input[4] + input[12]) & 0xFFFF) == 166;
result &= ((input[12] *  input[15]) & 0xFFFF) == 8769;
result &= ((input[15] + input[1]) & 0xFFFF) == 223;
result &= ((input[1] - input[9]) & 0xFFFF) == 5;
result &= ((input[9] - input[14]) & 0xFFFF) == 65527;
result &= ((input[14] *  input[7]) & 0xFFFF) == 13572;
result &= ((input[7] ^ input[0]) & 0xFFFF) == 37;
result &= ((input[0] *  input[11]) & 0xFFFF) == 8400;
result &= ((input[11] - input[6]) & 0xFFFF) == 65528;
result &= ((input[6] *  input[10]) & 0xFFFF) == 7797;
result &= ((input[10] + input[5]) & 0xFFFF) == 119;

    return result;
}

