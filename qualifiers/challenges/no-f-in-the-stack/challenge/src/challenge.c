#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>


void blah()
{
    system("");
}


void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main(int argc, char** argv, char** envp)
{
    init();

    uintptr_t stack[2];
    for (int i = 0; i < 1000; i ++)
    {
        printf("Addr pls: ");
        uintptr_t addr = 0;
        scanf("%" SCNuPTR, &addr);
        if (addr == 0)
        {
            break;
        }

        char printed_addr[0x10] = {0};
        sprintf(printed_addr, "%" PRIuPTR, addr);
        sscanf(printed_addr, "%" SCNxPTR, &stack[i]);

        if (stack[i] == 0)
        {
            break;
        }
    }

    return 0;
}

