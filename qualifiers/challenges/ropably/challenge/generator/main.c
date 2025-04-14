#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

int checker(unsigned char *input);

int check() {
    size_t input_size = 0;
    char *input = NULL;
    ssize_t input_len = getline(&input, &input_size, stdin);
    if(input_len < 0) {
        free(input);
        return 0;
    }
    input[strcspn(input, "\n")] = 0;
    input_len = strlen(input);

    if(input_len != 16) {
        free(input);
        return 0;
    }

    int result = checker((unsigned char*)input);
    free(input);
    return result;
}

int main() {
    int result = check();

    if(result == 1) {
        puts("Yes");
        return EXIT_SUCCESS;
    } else {
        puts("No");
        return EXIT_FAILURE;
    }
}
