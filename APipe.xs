#define PERL_NO_GET_CONTEXT
/* need old swprintf on VC >= 2005 and Mingw */
#if !defined(_MSC_VER) || _MSC_VER >= 1400
#  define _CRT_NON_CONFORMING_SWPRINTFS
#endif
/* for STATUS_SUCCESS */
#include <ntstatus.h>
/* stop WinNT.h from defining a too limited for our use
   set of STATUS_* constants, since we use the full ones in ntstatus.h */
#define WIN32_NO_STATUS
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

/* nowadays in winternl.h, but not there in winternl.h for VC 2003, and
  winternl.h doesnt exist in VC 6, so there is no reliable place to find it,
  so just define it ourselves */
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

//#define DebugBreak __debugbreak
//#define DebugBreak nothing
//static void nothing() {0;}

/* special debugging mode, basically asserts are on */
#define DBGAPIPE

/* keeping this off, otherwise Perl lang level fds/handles will be valid in the
  child proc, there is no reason for them to be valid there, since the child proc
  and the child proc's c lib is unaware they exist (since we and neither does
  win32 perl supply a lpReserved2 in STARTUPINFO), and the NT kernel has to
  duplicate the handles, and tear them down, for the child proc, even tho
  the child proc will never use them or know about them (they are visible with
  ProcMon and Ntobjects tho), also inheriting handles in rare cases can make the
  child proc hang in kernel mode on child proc exit during handle teardown
  https://rt.perl.org/Public/Bug/Display.html?id=123402 */

//#define INHERIT_HANDLES


/* waitpid style information is useless and should not be used for detecting
   end of TAP stream condition, the main TAP child proc can launch a child proc
   to emmit TAP, then exit itself, and the child proc finished the "all passing"
   test stream,

   The NOTIFY_ON_PROC_END also has a (fixable) race condition in this code
   that fails asserts, where the process exit event comes while there is an
   in-flight read still going on, so the APROC * is freed, then later the final
   read packet comes in, with an freed APROC * in it, SEGV then. This will have
   to be fixed if NOTIFY_ON_PROC_END is ever revived.

   Maybe waitpid is needed if Test::Harness wants the exit code, does it want
   the exit code?
   */
#define NOTIFY_ON_PROC_END


/* some statistics that are printed in END */
//#define STATS

/* use NT Native API, use NtReadFile instead of ReadFile */
//#define NATIVE

/*************************************************************************
 *END OF CONFIGURATION AREA
 *************************************************************************
 */

/* NTSTATUS definition inside ntsecapi.h
   ntsecapi.h and winternl.h are mutually exclusive,
   but we dont use winternl.h (see below) */
#include <ntsecapi.h>

/* used in NATIVE and Win32 build options */
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef DWORD (WINAPI* pfnGetProcID)(HANDLE h);
pfnGetProcID MyGetProcessId;

#ifdef NATIVE
/* In VC 2003's winternl.h NtClose is declared by accident without
   NTAPI/__stdcall, but in the normal way of doing things, that declaration will
   never be used, since MS says to is GetProcAddress, instead we make our own
   import lib. So those declarations were never supposed to be used.
   If we declaring NtClose with NTAPI that causes error C2373,
   this declaration problem was corrected later by MS, by atleast SDK 7.1, so if
   the SDK is new enough, it wont have that declaration bug. But MS doesn't use
   __declspec(dllimport) inside NTAPI (less efficient), so just dont use
   winternl.h at all on any CC because of those 2 reasons */

#  include "APNt.h"

/* BOOL APCreateIoCompletionPort(HANDLE * NewHandle) */
 /* last arg sets 1 thread, Perl doesn't process TAP with many to many layout */
#  define APCreateIoCompletionPort(NewHandle) \
    (NT_SUCCESS(NtCreateIoCompletion((NewHandle), IO_COMPLETION_ALL_ACCESS, NULL, 1)) ? TRUE : FALSE)
__forceinline
BOOL
APBindFileIoPort(HANDLE FileHandle, HANDLE Port, ULONG_PTR Key) {
    /* save some C stack, IoStatusBlock is mandatory, but we dont use it */
    union {
        IO_STATUS_BLOCK IoStatusBlock;
        FILE_COMPLETION_INFORMATION CompletionInformation;
    } Info;

    NTSTATUS Status;
    Info.CompletionInformation.Port = Port;
    Info.CompletionInformation.Key = (PVOID)Key;
    Status = NtSetInformationFile(FileHandle,
                                      &Info.IoStatusBlock,
                                      &Info.CompletionInformation,
                                      sizeof(FILE_COMPLETION_INFORMATION),
                                      FileCompletionInformation);
    return NT_SUCCESS(Status) ? TRUE : FALSE;
}

/* The below I tried with the bad winternl.h declaration, but you dont get the
   __declspec(dllimport) optimization by doing this */
//#define CloseHandle(x) (NT_SUCCESS(((NTSTATUS(NTAPI *)(HANDLE))NtClose)(x)) ? TRUE : FALSE)

/* These are here for a tiny bit of perf increase, no real reason unlike NtReadFile */
/* The :? optimizes away if DBGAPIPE is off */
#define CloseHandle(x) (NT_SUCCESS(NtClose(x)) ? TRUE : FALSE)
#define PostQueuedCompletionStatus(Port, BytesTransferred, Key, Overlapped) \
    (NT_SUCCESS(NtSetIoCompletion(Port, Key, Overlapped, STATUS_SUCCESS, BytesTransferred)) ? TRUE : FALSE)
#else
 /* last arg sets 1 thread, Perl doesn't process TAP with many to many layout */
#  define APCreateIoCompletionPort(NewHandle) ((*(NewHandle) = CreateIoCompletionPort(INVALID_HANDLE_VALUE,NULL,0, 1)) ? TRUE : FALSE)
#  define APBindFileIoPort(Handle, Port, Key) (CreateIoCompletionPort(Handle, Port, Key, 0) ? TRUE : FALSE)
#endif

#ifdef DBGAPIPE
/* check the "BOOL" ret value of kernel32 API things that normally are
   unchecked because they will never fail, this is on only for debuging, turn
   off for release */
#  define DBGCHKBOOL(x) if(!(x)) DebugBreak()
/* set struct members to NULL before freeing them, useful for step C debugging */
#  define DBGSETNULL(x) (x) = NULL
#else
#  define DBGCHKBOOL(x) (x)
#  define DBGSETNULL(x)
#endif

#ifndef SvREFCNT_dec_NN
#  define SvREFCNT_dec_NN(sv) SvREFCNT_dec(sv)
#endif

#define PERL_VERSION_LE(R, V, S) (PERL_REVISION < (R) || \
(PERL_REVISION == (R) && (PERL_VERSION < (V) ||\
(PERL_VERSION == (V) && (PERL_SUBVERSION <= (S))))))

/* less efficient on very old perls, but oh well */
#if PERL_VERSION_LE(5, 9, 4)
#  define sv_usepvn_flags(sv, ptr, len, flags) sv_usepvn(sv, ptr, len)
#endif

/* note an LPOVERLAPPED can be cast to APROC * and back */
/*todo this struct has alignment holes, rethink the order of members one day */
typedef struct {
#ifndef NATIVE
/* we dont need Offset and hEvent members for Native API, they are only used by
  ReadFile/GetOverlappedResult */
    union {
        OVERLAPPED overlapped;
#endif
        IO_STATUS_BLOCK IoStatus;
#ifndef NATIVE
    };
#endif
    HANDLE hStdOut;
    /* even tho the parent proc never uses the hWritePipe, only the child proc
      does, the parent proc must keep this handle alive (Win32 handles are ref
      counted by the kernel) until the child proc exits, otherwise, the moment
      the child proc exists, all buffered unread data in the pipe is lost,
      TAP::Harness isn't fast/efficient enough on a multicore machine to keep
      up with a child proc very quickly emitting TAP, with print()s for example.
      Basically the STATUS_PIPE_BROKEN error is not end of data, but is end of
      process.
      */
    HANDLE hWritePipe; 
#ifdef NOTIFY_ON_PROC_END
    HANDLE hProcess;
    HANDLE hWaitObj;
/* should times and exit code be in APROC sturct and fetched in threadpool thread
  or it is waste of mem, and perl thread should do this in next()? */
    FILETIME CreationTime;
    FILETIME ExitTime;
    FILETIME KernelTime;
    FILETIME UserTime;
#endif
    SV * opaque;
    char * buffer;
#ifdef PERL_IMPLICIT_SYS
    HANDLE Port; /* not owned here, the MY_CXT var is the owner of the IOCP */
#endif
    DWORD PendingWaiters; /* undelivered active IOCPs containing this APROC * */
#ifdef NOTIFY_ON_PROC_END
    DWORD ExitCode;
#endif
#ifdef DBGAPIPE
    char InWait;
#endif
} APROC;


/* common const struts */
const char empty_aproc [sizeof(APROC)] = {0};
const SECURITY_ATTRIBUTES WritePipeAttributes = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
#ifndef INHERIT_HANDLES
const STARTUPINFO StartupInfo = {sizeof(StartupInfo), 0};
#endif


#define KEY_READ_FINISHED 0
#ifdef NOTIFY_ON_PROC_END
#  define KEY_PROCESS_EXITED 1
#endif

DWORD PipeID = 0;

DWORD GlobalWaiters = 0;
    
#if PERL_IMPLICIT_CONTEXT
#  define GETNEXTPIPEID() InterlockedIncrement(&PipeID)
#else
#  define GETNEXTPIPEID() ++PipeID
#endif

#define PIPE_BUF_SIZE 4096 /* if it is page sized, there is the possibility that
                             the internal implementation might splice pages in
                             kernel mode or less copies done in kernel mode
                             since the page was locked in phy mem, and made
                             visible to the other process in kernel mode, so
                             the writer I/O call directly copies to the reader's
                             memory block, IDK if NPFS does this, but MS could
                             always add it in the future, Perl in win32.c uses
                             512 */

#define MY_CXT_KEY "Win32::Internet::_guts" XS_VERSION
typedef struct {
#ifdef STATS
    double AvgRead;
#endif
    HANDLE Port;
#ifdef STATS
    DWORD MaxRead;
    DWORD MinRead;
#endif
} my_cxt_t;

START_MY_CXT

static void
init_MY_CXT(my_cxt_t * cxt) /* doesn't need pTHX */
{
#ifdef STATS
    cxt->AvgRead = 0.0;
    cxt->MaxRead = 0;
    cxt->MinRead = -1;
#endif
    DBGCHKBOOL(APCreateIoCompletionPort(&cxt->Port));
}

#ifdef NOTIFY_ON_PROC_END
/* turns a WFSO/WFMO event (process exit in this case) into an IOCP queue event */
/* reads are more likely to happen than process exits*/
VOID CALLBACK WaitFunc( APROC * aproc, BOOLEAN TimerOrWaitFired) {
    aproc->InWait = 1;
    if(TimerOrWaitFired == TRUE)
        DebugBreak();
    DBGCHKBOOL(GetExitCodeProcess(aproc->hProcess, &aproc->ExitCode));
    DBGCHKBOOL(GetProcessTimes(aproc->hProcess, 
    &aproc->CreationTime,
    &aproc->ExitTime,
    &aproc->KernelTime,
    &aproc->UserTime));
    /* close the write handle, the async read will block (forever) until this handle is freed by both this (parent) perl proc, and the child proc */
    //Sleep(2000);
    DBGCHKBOOL(CloseHandle(aproc->hWritePipe));
    DBGSETNULL(aproc->hWritePipe);
#ifdef PERL_IMPLICIT_SYS
    DBGCHKBOOL(PostQueuedCompletionStatus(
        aproc->Port,
        0, // to save mem, send exit code through dwNumberOfBytesTransferred and not in the aproc struct????
        KEY_PROCESS_EXITED,
        (LPOVERLAPPED)aproc
    ));
#else
    DBGCHKBOOL(PostQueuedCompletionStatus(
        MY_CXT.Port,
        0,
        KEY_PROCESS_EXITED,
        (LPOVERLAPPED)aproc
    ));
#endif
    aproc->InWait = 0; //segv risk on this line, we might be freed
}

#endif /* #ifdef NOTIFY_ON_PROC_END */


void
StartRead(APROC * aproc) {
    dTHX;
    dMY_CXT;
#ifndef NATIVE
    BOOL ret;
    DWORD err;
#else
    NTSTATUS Status;
#endif
    GlobalWaiters++;
    aproc->PendingWaiters++;
#ifdef DBGAPIPE
    if(aproc->buffer)
        DebugBreak();
#endif
    Newx(aproc->buffer, PIPE_BUF_SIZE+1, char);
#ifndef NATIVE
    ret = ReadFile(
      aproc->hStdOut,
      aproc->buffer,
      PIPE_BUF_SIZE,
      NULL,
      &aproc->overlapped
    );
    if(ret == FALSE) {
        err = GetLastError();
        /* ERROR_IO_PENDING 997 (0x3E5) */
        if (err != ERROR_IO_PENDING) {
            /*ERROR_BROKEN_PIPE 109 (0x6D)*/
            if(err == ERROR_BROKEN_PIPE)
                /* must manually the queue the packet since this ReadFile
                   failed syncronously */
                aproc->overlapped.Internal = STATUS_PIPE_BROKEN;
            else
/* Unknown how to convert an arbitrary win32 err code to
   aproc->overlapped.Internal NTSTATUS code. An HRESULT is a more expansive
   version of NTSTATUS, and there is an API to go from Win32 error code to
   HRESULT but IDK how accurate the conversion, so i wont try it.
   Using NtReadFile to get the NTSTATUS code is easiest. */
                DebugBreak();
#else
    Status = NtReadFile(aproc->hStdOut,         /* FileHandle */
                        NULL,                   /* Event */
                        NULL,                   /* ApcRoutine */
                        aproc,                  /* ApcContext */
                        &aproc->IoStatus,       /* IoStatusBlock */
                        aproc->buffer,          /* Buffer */
                        PIPE_BUF_SIZE,          /* Length */
                        NULL,                   /* ByteOffset */
                        NULL);                  /* Key */
    if(Status != STATUS_SUCCESS && Status != STATUS_PENDING) {
        if(1) { /* match Win32 code flow */
            aproc->IoStatus.Status = Status;
#endif
#ifdef PERL_IMPLICIT_SYS
            DBGCHKBOOL(PostQueuedCompletionStatus(
                aproc->Port,
                0,
                KEY_READ_FINISHED,
                (LPOVERLAPPED)aproc
            ));
#else
            DBGCHKBOOL(PostQueuedCompletionStatus(
                MY_CXT.Port,
                0,
                KEY_READ_FINISHED,
                (LPOVERLAPPED)aproc
            ));
#endif
        }
    }
    /* else sync successful completion generates packets */
}

FreeAPROC(pTHX_ APROC * aproc) {
    /* buffer should have been freed in caller. If PendingWaiters is is not 0
       something else might deliver an IOCP packet with a freed APROC * */
    if(aproc->buffer || aproc->PendingWaiters != 0)
	DebugBreak();

#ifdef NOTIFY_ON_PROC_END
    {
        BOOL ret;
	DWORD err;
#ifdef DBGAPIPE
        DWORD start = GetTickCount();
        DWORD end;
#endif
        ret = UnregisterWait(aproc->hWaitObj);
        if(!ret)
	    err = GetLastError();
#ifdef DBGAPIPE
        end = GetTickCount();
/* this isn't supposed to block, but GTC is a low res counter remember */
        if(end - start > 64)
            DebugBreak();
#endif
/* ERROR_IO_PENDING is not acceptable, the callback was supposed to be 1 shot */
        //DBGCHKBOOL(ret);
        DBGSETNULL(aproc->hWaitObj);
    }
#endif
    SvREFCNT_dec_NN(aproc->opaque);
    DBGSETNULL(aproc->opaque);

#ifdef NOTIFY_ON_PROC_END
    DBGCHKBOOL(CloseHandle(aproc->hProcess));
    DBGSETNULL(aproc->hProcess);
#endif
    //DBGCHKBOOL(CloseHandle(aproc->hWritePipe));
    //DBGSETNULL(aproc->hWritePipe);
/* XXX maybe we can recycle pipes for the next process instead of freeing them ??? */
    DBGCHKBOOL(CloseHandle(aproc->hStdOut));
    DBGSETNULL(aproc->hStdOut);
    Safefree(aproc);
}

/* get rid of CRT startup code on MSVC, it is bloat, this module uses 2
   libc functions, memcpy and swprintf, they dont need initialization */
#ifdef _MSC_VER
BOOL WINAPI _DllMainCRTStartup(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved )
{
    BOOL ret;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        ret = DisableThreadLibraryCalls(hinstDLL);
        if(!ret)
            return ret;
        ret = cBOOL(MyGetProcessId = (pfnGetProcID) GetProcAddress(GetModuleHandle("KERNEL32.DLL"),"GetProcessId"));
        return ret;
    }
    return TRUE;
}
#else
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved )
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        return cBOOL(MyGetProcessId = (pfnGetProcID) GetProcAddress(GetModuleHandle("KERNEL32.DLL"),"GetProcessId"));
    }
}

#endif


MODULE = Win32::APipe		PACKAGE = Win32::APipe

BOOT:
{
    MY_CXT_INIT;
    init_MY_CXT(&MY_CXT);
}

#_if PERL_IMPLICIT_CONTEXT for embedding, but no ithreads, then CLONE is never
# called, so remove it then

#ifdef USE_ITHREADS
void CLONE (...)
CODE:
{
    MY_CXT_CLONE; /* possible declaration */
    init_MY_CXT(&MY_CXT);
    return; /* skip implicit PUTBACK, returning @_ to caller, more efficient*/
}

#endif


void END(...)
PREINIT:
    dMY_CXT;
PPCODE:
    /* according to MSDN make sure the IOCP is rundown before this call executes */
    DBGCHKBOOL(CloseHandle(MY_CXT.Port));
#ifdef STATS
    warn("AvgRead %f MaxRead %u MinRead %u", MY_CXT.AvgRead, MY_CXT.MaxRead, MY_CXT.MinRead);
#endif
    return; /* skip implicit PUTBACK, returning @_ to caller, more efficient*/

# $GetLastError_style_error_code = run($cmd, $opaque);
#
# Launches the process in $cmd and adds it to the global pipe queue. STDOUT of
# the process will be captured and returned in blocks as it comes in over time
# in next(). STDIN and STDERR for the child proc will be whatever they are of
# the process the called run() (this perl process). $opaque is some scalar that
# will be saved and returned in next() to you each time a data block from
# process becomes available. This way, with $opaque, you know what process the
# the block came from.
#
# returns GLR error code or 0 for sucess
DWORD
run(cmd, opaque, merge, pid)
    char * cmd
    SV * opaque
    bool merge
    SV * pid
PREINIT:
    APROC * aproc;
CODE:
    Newxz(aproc, 1, APROC);
    {
    WCHAR PipeName [(sizeof("\\\\.\\pipe\\PerlAPipe")-1)+8+(sizeof(".")-1)+8+1];
    swprintf(   PipeName,
                L"\\\\.\\pipe\\PerlAPipe%08x.%08x",
                GetCurrentProcessId(),
                GETNEXTPIPEID());
    aproc->hStdOut =  CreateNamedPipeW(
      PipeName,
      PIPE_ACCESS_INBOUND
      |FILE_FLAG_FIRST_PIPE_INSTANCE /* sanity check */
      |FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE
      |PIPE_READMODE_BYTE
      |PIPE_WAIT, /* we are async, but ref implementation MyCreatePipeEx does this*/
      1, /* 1 instance*/
      PIPE_BUF_SIZE,
      PIPE_BUF_SIZE,
      120*1000, /* from MyCreatePipeEx and reactos's CreatePipe, 120 seconds */
      NULL/*LPSECURITY_ATTRIBUTES lpSecurityAttributes*/
    );

    DBGCHKBOOL(aproc->hStdOut);
    {
        dMY_CXT;
/* VC optimizer in -O1 fails to optimize MY_CXT.Port to 1 read of MY_CXT
  instead of 2, if 2 are written (one for aproc, one for APBindFileIoPort) */
        HANDLE Port = MY_CXT.Port;
#ifdef PERL_IMPLICIT_SYS
        /* WaitFunc needs to know what IOCP to deliver its exit event on, aTHX
           here is another choice, but remember WaitFunc is running in a random
           thread so using the interp from the wrong OS thread is risky so
           just put the IOCP here to KISS */
        aproc->Port = Port;
#endif
        DBGCHKBOOL(APBindFileIoPort(
          aproc->hStdOut,
          Port,
          KEY_READ_FINISHED
        ));
    }

    aproc->hWritePipe = CreateFileW(
                        PipeName,
                        GENERIC_WRITE,
                        0,
                        (LPSECURITY_ATTRIBUTES)&WritePipeAttributes,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, /* b88 added overlapped, remove? */
                        NULL
                      );
#ifdef DBGAPIPE
    if (INVALID_HANDLE_VALUE == aproc->hWritePipe)
        DebugBreak();
#endif
    } //scope WCHAR PipeName
    {
    PROCESS_INFORMATION ProcessInformation;
#ifdef INHERIT_HANDLES
    STARTUPINFO StartupInfo;
#else
    /* use const global StartupInfo */
    HANDLE oldout = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE olderr;
    /* this needs a critical section for thread safety, or use create suspended
        and DuplicateHandle and WriteProcessMemory to new proc's PEB's
        _RTL_USER_PROCESS_PARAMETERS->StandardOutput and friends like CreateProcess
        does internally, Perl had problems with this/dup() in the past, where the
        effects show up in other ithreads/psuedoprocs */
    SetStdHandle(STD_OUTPUT_HANDLE, aproc->hWritePipe);
    if(merge) {
        olderr = GetStdHandle(STD_ERROR_HANDLE);
        SetStdHandle(STD_ERROR_HANDLE, aproc->hWritePipe);
    }
#endif
#ifdef INHERIT_HANDLES
    StartupInfo.cb = sizeof(StartupInfo);
    memset(&StartupInfo.lpReserved, 0, offsetof(STARTUPINFO,hStdInput)-offsetof(STARTUPINFO,lpReserved));
    StartupInfo.dwFlags    = STARTF_USESTDHANDLES; /* egh zeroed by the memset */
    StartupInfo.hStdInput  = (HANDLE)_get_osfhandle(0);
    StartupInfo.hStdOutput = hWritePipe;
    StartupInfo.hStdError  = merge ? hWritePipe : (HANDLE)_get_osfhandle(2);
#endif

    if (CreateProcess(NULL,		/* search PATH to find executable */
		       cmd,		/* executable, and its arguments */
		       NULL,		/* process attributes */
		       NULL,		/* thread attributes */
#ifdef INHERIT_HANDLES
		       TRUE,		/* inherit handles */
#else
		       FALSE,		/* inherit handles */
#endif
                       /* change to FALSE, then create suspended, then duplicate handles , then resume ?*/
                       /*actually std hnds r special cased to be duped in StuffStdHandle */
		       CREATE_NEW_PROCESS_GROUP,		/* creation flags */
		       NULL,	/* inherit environment */
		       NULL,		/* inherit cwd */
		       (LPSTARTUPINFO)&StartupInfo,
		       &ProcessInformation)) {
        sv_setiv(pid, MyGetProcessId(ProcessInformation.hProcess));
#ifdef NOTIFY_ON_PROC_END
        aproc->hProcess = ProcessInformation.hProcess;
#else
        DBGCHKBOOL(CloseHandle(ProcessInformation.hProcess));
#endif
        DBGCHKBOOL(CloseHandle(ProcessInformation.hThread));
        RETVAL = ERROR_SUCCESS;
    }
    else
        RETVAL = GetLastError();
#ifndef INHERIT_HANDLES
    SetStdHandle(STD_OUTPUT_HANDLE, oldout);
    if (merge)
        SetStdHandle(STD_ERROR_HANDLE, olderr);
#endif
    } /* scope CreateProcess */
    if(RETVAL == ERROR_SUCCESS) {
        dMY_CXT;
#ifdef NOTIFY_ON_PROC_END
        DBGCHKBOOL(RegisterWaitForSingleObject(
            &aproc->hWaitObj,
            aproc->hProcess,
            WaitFunc,
            aproc,
            INFINITE,
            WT_EXECUTEONLYONCE));
        GlobalWaiters++;
        aproc->PendingWaiters++;
        aproc->ExitCode = STILL_ACTIVE;
#endif
        /* save the caller's opaque SV*, this is probably an RV to a blessed SV */
        aproc->opaque = SvREFCNT_inc_simple_NN(opaque);
        StartRead(aproc);
    } else {
        DBGCHKBOOL(CloseHandle(aproc->hStdOut));
        DBGSETNULL(aproc->hStdOut);
        Safefree(aproc);
    }
OUTPUT:
    RETVAL

# $opaque = Win32::APipe::next($buffer);
#
# This returns the next STDOUT pipe data block off the global pipe queue.
# This call will block until the a data block is available from any actively
# running processes started with Win32::APipe::run. If there are no actively
# running processes, next() hangs forever, so dont do that.
#
# The retval is the $opaque scalar associated with the process, in
# Win32::APipe::run. If $buffer is empty string, then the pipe and process
# has been terminated and no further data blocks will come out of that process.
# You are responsible for scheduling processes, and not hanging if there are no
# actively running processes.
#
#returns $opaque
#bufferSV is written into
void
next(bufferSV)
    SV* bufferSV
PREINIT:
    dMY_CXT;
    ULONG_PTR CompletionKey;
    APROC * aproc;
#ifdef NATIVE
    IO_STATUS_BLOCK IoStatus;
#  define NumberOfBytes (IoStatus.Information)
#else
    DWORD NumberOfBytes;
#endif
CODE:
{   /* use CODE: so SP isn't moved back so the SETs below works */
#ifdef NOTIFY_ON_PROC_END
    restart:
#endif
    if(GlobalWaiters == 0)
        croak("you can't next() when there is no work");
#ifndef NATIVE
{   BOOL ret = GetQueuedCompletionStatus(
        MY_CXT.Port,
        &NumberOfBytes,
        &CompletionKey,
        (LPOVERLAPPED*)&aproc,
        INFINITE
    );
    /* a serious error happened, no packet received, do not proceed */
    if(ret == FALSE && aproc == NULL)
        DebugBreak();
}
#else
{
    NTSTATUS Status = NtRemoveIoCompletion(
        MY_CXT.Port,
        (PVOID *)&CompletionKey,
        (PVOID *)&aproc,
        &IoStatus,
        NULL /* infinity */
    );
    /* a serious error happened, no packet received, do not proceed */
    if(!NT_SUCCESS(Status))
        DebugBreak();
#ifdef DBGAPIPE
    /* these 2 better match according to the NT API */
     if(memcmp(&aproc->IoStatus, &IoStatus, sizeof(IO_STATUS_BLOCK)) != 0)
        DebugBreak();
#endif
}
#endif
    GlobalWaiters--;
    aproc->PendingWaiters--;
    SvREFCNT_inc_simple_NN(aproc->opaque);
    /* 1 scalar in, 1 scalar out, so use SETs with no PUTBACK since SP didn't move */
    SETs(sv_2mortal(aproc->opaque));
    if(CompletionKey == KEY_READ_FINISHED) {
        char * buffer = aproc->buffer;
        aproc->buffer = NULL; /* rmv later */
        /* note here, NumberOfBytes might be less than PIPE_BUF_SIZE, so we are
          undershooting the real length of the mem block, a realloc that returns
          the same ptr might happen, I dont see any way around it */
        /* XXX, do we maintain state on how full this buffer is, if its not full
          yet, do we do another async ReadFile and "goto" to GetQueuedCompletionStatus
          and wait again, this way Perl 5 code doesn't get <100 byte or low 100s
          of bytes, but many KBs of bytes to process, evaluate the numbers
          returned by the STATS feature on what avg read size is.
          What about newlines, should we always restart the read and read more
          until atleast 1 newline is found in the block? what if 4096 bytes go
          by with no newline? what about a test file that outputs many KBs of
          NULL bytes, and no newline ever? do we realloc the buffer up and up
          until either newline appears or end of stream? */
        /* not using GetOverlappedResult, dont need its features/bloat */
        /* 0xC000014B 3221225803  STATUS_PIPE_BROKEN */
        if(NT_SUCCESS(aproc->IoStatus.Status)) {
            buffer[NumberOfBytes] = '\0';
#ifdef STATS
            /* exclude 0 byte reads, they are in-band "signalling" I/O, not data */
            //if(NumberOfBytes) {
                MY_CXT.MinRead = min(MY_CXT.MinRead, NumberOfBytes);
                MY_CXT.MaxRead = max(MY_CXT.MaxRead, NumberOfBytes);
                MY_CXT.AvgRead = (MY_CXT.AvgRead+NumberOfBytes)/2.0;
            //}
#endif
            sv_usepvn_flags(bufferSV, buffer, NumberOfBytes, SV_HAS_TRAILING_NUL);
            /* a 0 byte read means end of stream */
#ifdef DBGAPIPE
            /*  STATUS_PIPE_BROKEN is end of stream, not STATUS_SUCCESS
                investigate if this trips */
            if(NT_SUCCESS(aproc->IoStatus.Status) && NumberOfBytes == 0)
                DebugBreak();
#endif
            //rmv later
            //if(NumberOfBytes)
                StartRead(aproc);
            //else {
            //    DebugBreak();
            //    FreeAPROC(aTHX_ aproc);
            //}
        }
        else if( aproc->IoStatus.Status == STATUS_PIPE_BROKEN ) {
            Safefree(buffer);
            goto non_read_event; /* wait for KEY_PROCESS_EXITED event */
        }
        else
            DebugBreak(); /* unknown error happened on the async read */
    }
#ifdef NOTIFY_ON_PROC_END
    else if (CompletionKey == KEY_PROCESS_EXITED) {
        non_read_event:
        if(aproc->PendingWaiters == 0) {
            HV * hv = newHV();
            sv_replace(bufferSV, newRV_noinc((SV*)hv));
#define SETFILETIME(hv, aproc, val) hv_store(hv, #val, sizeof("" #val "")-1, newSVpvn((char *)&aproc->val, sizeof(aproc->val)), 0)
            SETFILETIME(hv, aproc, CreationTime);
            SETFILETIME(hv, aproc, ExitTime);
            SETFILETIME(hv, aproc, KernelTime);
            SETFILETIME(hv, aproc, UserTime);
            hv_store(hv, "ExitCode", sizeof("ExitCode")-1, newSVuv(aproc->ExitCode), 0);
            FreeAPROC(aTHX_ aproc);
        }
        else
            goto restart; /* there is an in flight read or end of process wait*/
    }
#endif
#ifdef DBGAPIPE
    else /* unknown completion key */
        DebugBreak();
#endif
    return; /* skip implicit PUTBACK */
#undef NumberOfBytes
}

DWORD
status_to_sig(status)
    DWORD status
CODE:
# ifndef STATUS_FAILED_STACK_SWITCH
#  define STATUS_FAILED_STACK_SWITCH ((NTSTATUS) 0xC0000373L)
# endif
# ifndef STATUS_HEAP_CORRUPTION
#  define STATUS_HEAP_CORRUPTION ((NTSTATUS) 0xC0000374L)
# endif
#  ifndef STATUS_INVALID_CRUNTIME_PARAMETER
#    define STATUS_INVALID_CRUNTIME_PARAMETER ((DWORD)0xC0000417L)
#  endif
#  ifndef SIGBUS
#    define	SIGBUS	10	/* bus error */
#  endif
#  ifndef SIGTRAP
#    define	SIGTRAP	5
#  endif
#  ifndef SIGSYS
#    define	SIGSYS	12
#  endif
/* https://github.com/pathscale/stdcxx/blob/master/util/exec.cpp */
    switch(status) {
        case STATUS_BREAKPOINT:
            RETVAL = SIGTRAP;
            break;
        case STATUS_ACCESS_VIOLATION:
            RETVAL = SIGSEGV;
            break;
        case STATUS_STACK_OVERFLOW:
            RETVAL = SIGSEGV;
            break;
        case STATUS_HEAP_CORRUPTION:
            RETVAL = SIGSEGV;
            break;
        case STATUS_STACK_BUFFER_OVERRUN:
            RETVAL = SIGSEGV;
            break;
        case STATUS_IN_PAGE_ERROR:
            RETVAL = SIGBUS;
            break;
        case STATUS_ILLEGAL_INSTRUCTION:
            RETVAL = SIGILL;
            break;
        case STATUS_PRIVILEGED_INSTRUCTION:
            RETVAL = SIGILL;
            break;
        case STATUS_FLOAT_DENORMAL_OPERAND:
            RETVAL = SIGFPE;
            break;
        case STATUS_FLOAT_DIVIDE_BY_ZERO:
            RETVAL = SIGFPE;
            break;
        case STATUS_FLOAT_INEXACT_RESULT:
            RETVAL = SIGFPE;
            break;
        case STATUS_FLOAT_INVALID_OPERATION:
            RETVAL = SIGFPE;
            break;
        case STATUS_FLOAT_OVERFLOW:
            RETVAL = SIGFPE;
            break;
        case STATUS_FLOAT_UNDERFLOW:
            RETVAL = SIGFPE;
            break;
        case STATUS_INTEGER_DIVIDE_BY_ZERO:
            RETVAL = SIGFPE;
            break;
        case STATUS_INTEGER_OVERFLOW:
            RETVAL = SIGFPE;
            break;
        case STATUS_FLOAT_STACK_CHECK:
            RETVAL = SIGFPE; /* note, ignore code on google that says SIGSTKFLT, this is a rare in unix signal, and MS's _XcptActTab says STATUS_FLOAT_STACK_CHECK is SIGFPE */
            break;
        case STATUS_INVALID_PARAMETER:
            RETVAL = SIGSYS;
            break;
        case STATUS_INVALID_CRUNTIME_PARAMETER:
            RETVAL = SIGSYS;
        default:
            RETVAL = 0;
    }
OUTPUT:
    RETVAL
