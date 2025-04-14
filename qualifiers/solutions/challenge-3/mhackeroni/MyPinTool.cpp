#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdint.h>
#include <string.h>
using std::cerr;
using std::endl;
using std::string;

VOID PrintName(const char *rtn_name, unsigned long long rdi_val, unsigned long long rsi_val) {
    fprintf(stderr, "%s\n", rtn_name);
}

VOID Routine(RTN rtn, VOID* v)
{
    RTN_Open(rtn);
    std::string RoutineName = RTN_Name(rtn);

    const char *Name = RoutineName.c_str();
    char* FinalName = (char *)malloc(sizeof(char) * strlen(Name) + 1);
    strcpy(FinalName, Name);

    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)PrintName, IARG_PTR, FinalName, IARG_REG_VALUE, REG_RDI, IARG_REG_VALUE, REG_RSI, IARG_END);
    RTN_Close(rtn);
}

int main(int argc, char* argv[])
{

    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
        return 0;

    RTN_AddInstrumentFunction(Routine, 0);
    PIN_StartProgram();
    return 0;
}

