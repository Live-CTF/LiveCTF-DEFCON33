#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <ctype.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdexcept>

class Something
{
public:
    Something()
    {
        printf("Constructing Something...\n");
    }
    ~Something()
    {
        printf("Destructing Something...\n");
    }
};

void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main(int argc, char** argv, char** envp);

void throw_exception()
{
    Something var;
    
    // todo: probably keep these
    printf("main: %p\n", &main);
    printf("var: %p\n", &var);
    printf("printf: %p\n", &printf);

    // Only let them write to the EH sections
    uintptr_t main_segment = (uintptr_t)(&main) & ~0xFFF;

    // Offsets lovingly hand copied out of binja
    // If these end up being wrong in the final bin, lol, lmao even.
    uintptr_t eh_start = main_segment + 0x10b8;
    uintptr_t eh_end = main_segment + 0x12d4;

    mprotect((void*)(main_segment + 0x1000), 0x1000, PROT_READ|PROT_WRITE);

    while (1)
    {
        printf("Where to write?\n");
        uint64_t* addr = 0;
        scanf("%" SCNx64, (uint64_t*)&addr);

        if ((uintptr_t)addr < eh_start || (uintptr_t)addr >= eh_end)
        {
            printf("Wrong section!\n");
            continue;
        }

        printf("What to write?\n");
        scanf("%" SCNx64, addr);

        uint64_t again = 0;
        printf("Write again?\n");
        scanf("%" SCNx64, &again);
        if (!again)
        {
            break;
        }
    }

    mprotect((void*)(main_segment + 0x1000), 0x1000, PROT_READ);

    throw std::runtime_error("Whee");
}

int main(int argc, char** argv, char** envp)
{
    init();

    try
    {
        throw_exception();
    }
    catch (const std::exception& exc)
    {
        printf("Caught exception: %s\n", exc.what());
    }

    return 0;
}
