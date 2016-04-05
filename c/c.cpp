// c.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <io.h>
#include <windows.h>

int main(int argc,  char * argv[])
{
    HANDLE o, o2;
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    //DebugBreak();
    o = (HANDLE)_get_osfhandle( 1 );
    o2 = GetStdHandle(STD_OUTPUT_HANDLE);
    fprintf(stderr, "o %x %x\n", o, o2);
    return 0;
}

