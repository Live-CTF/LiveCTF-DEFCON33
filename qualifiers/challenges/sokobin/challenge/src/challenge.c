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

#define GET_BIT(x, n) (((x) & (1 << (n))) >> (n))
#define SET_BIT(x, n, v) ((x & ~(1 << (n))) | ((!!(v)) << (n)))

typedef uint32_t row_t;
#define BOARD_W (CHAR_BIT * (sizeof(row_t) / sizeof(char)))
#define BOARD_H 32

void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void win(void)
{
    __asm__(
        "movq $0xfffffffffffffff0, %%rax\n"
        "andq %%rax, %%rsp\n"
    ::: "memory");
    system("/bin/sh");
}


struct state_t
{
    int32_t input;
    int16_t debug;
    int8_t px;
    int8_t py;
    row_t* board;
};


int main(int argc, char** argv, char** envp)
{
    struct state_t state;
    // All defined up here so that the stack layout is favorable
    // and gcc puts a bunch of zeroes right before our return address
    int64_t done;
    int8_t x;
    int8_t y;
    int8_t off;
    int8_t can_move;
    int8_t min_x;
    int8_t min_y;
    int8_t max_x;
    int8_t max_y;

    init();

    state.debug = 0;
    state.board = (row_t*)&state;
    state.px = 0;
    state.py = 0;
    done = 0;
    x = 0;
    y = 0;
    off = 0;
    can_move = 0;
    min_x = 0;
    min_y = 0;
    max_x = 0;
    max_y = 0;

#define GET_BOARD(x, y) GET_BIT(state.board[y], x)
#define SET_BOARD(x, y, n) state.board[y] = SET_BIT(state.board[y], x, n)
    
    // Helping you out
    state.board[12] = 0;
    state.board[13] = 0;
    state.board[14] = 0;
    state.board[15] = 0;
    for (y = 18; y < BOARD_H - 8; y ++)
    {
        // Okay now this is overt
        if (y != 18 && y != 19)
        {
            SET_BOARD(BOARD_W - 2, y, 0);
            SET_BOARD(BOARD_W - 1, y, 0);
        }
    }
    state.board[BOARD_H - 8] = 0x33333333;
    state.board[BOARD_H - 7] = 0;
    state.board[BOARD_H - 6] = 0xcccccccc;
    state.board[BOARD_H - 5] = 0;
    state.board[BOARD_H - 4] = 0x33333333;
    state.board[BOARD_H - 3] = 0;
    state.board[BOARD_H - 2] = 0xcccccccc;
    state.board[BOARD_H - 1] = 0;
    
    while (!done)
    {
        printf("Sokobin!\n");
        for (y = BOARD_H - 1; y >= 0; y --)
        {
            if (state.debug)
            {
                printf("%p: ", &state.board[y]);
            }
            for (x = 0; x < BOARD_W; x ++)
            {
                if (state.px == x && state.py == y)
                {
                    printf("@");
                }
                else
                {
                    printf("%c", ".o"[GET_BOARD(x, y)]);
                }
            }
            if (state.debug)
            {
                for (off = 0; off < sizeof(row_t); off ++)
                {
                    printf(" %02hhx", ((unsigned char*)(&state.board[y]))[off]);
                }
            }
            printf("\n");
        }
        do
        {
            state.input = getchar();

            if (state.input == EOF || state.input == 'q')
            {
                done = 1;
            }
            if (state.input == 'w')
            {
                can_move = 1;
                max_y = 0;
                for (y = state.py + 1; y <= BOARD_H; y ++)
                {
                    if (y >= BOARD_H)
                    {
                        can_move = 0;
                        break;
                    }
                    if (GET_BOARD(state.px, y) == 0)
                    {
                        max_y = y;
                        break;
                    }
                }
                if (can_move)
                {
                    state.py += 1;
                    for (y = max_y; y > state.py; y --)
                    {
                        SET_BOARD(state.px, y, 1);
                    }
                    SET_BOARD(state.px, state.py, 0);
                }
            }
            if (state.input == 'r')
            {
                can_move = 1;
                min_y = 0;
                for (y = state.py - 1; y >= -1; y --)
                {
                    if (y < 0)
                    {
                        can_move = 0;
                        break;
                    }
                    if (GET_BOARD(state.px, y) == 0)
                    {
                        min_y = y;
                        break;
                    }
                }
                if (can_move)
                {
                    state.py -= 1;
                    for (y = min_y; y < state.py; y ++)
                    {
                        SET_BOARD(state.px, y, 1);
                    }
                    SET_BOARD(state.px, state.py, 0);
                }
            }
            if (state.input == 's')
            {
                can_move = 1;
                max_x = 0;
                for (x = state.px + 1; x <= BOARD_W; x ++)
                {
                    if (x >= BOARD_W)
                    {
                        can_move = 0;
                        break;
                    }
                    if (GET_BOARD(x, state.py) == 0)
                    {
                        max_x = x;
                        break;
                    }
                }
                if (can_move)
                {
                    state.px += 1;
                    for (x = max_x; x > state.px; x --)
                    {
                        SET_BOARD(x, state.py, 1);
                    }
                    SET_BOARD(state.px, state.py, 0);
                }
            }
            if (state.input == 'a')
            {
                can_move = 1;
                min_x = 0;
                for (x = state.px - 1; x >= -1; x --)
                {
                    if (x < 0)
                    {
                        can_move = 0;
                        break;
                    }
                    if (GET_BOARD(x, state.py) == 0)
                    {
                        min_x = x;
                        break;
                    }
                }
                if (can_move)
                {
                    state.px -= 1;
                    for (x = min_x; x < state.px; x ++)
                    {
                        SET_BOARD(x, state.py, 1);
                    }
                    SET_BOARD(state.px, state.py, 0);
                }
            }
        } while (!isspace(state.input));
    }

    return 0;
}

