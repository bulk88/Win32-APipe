#define PERL_NO_GET_CONTEXT
/* need old swprintf on VC >= 2005 */
#if _MSC_VER >= 1400
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
/* NTSTATUS definition inside ntsecapi.h */
#include <ntsecapi.h>


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
   */
//#define NOTIFY_ON_PROC_END


/* some statistics that are printed in END */
#define STATS

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
typedef struct {
    OVERLAPPED overlapped;
    HANDLE hStdOut;
#ifdef NOTIFY_ON_PROC_END
    HANDLE hProcess;
    HANDLE hWaitObj;
#endif
    SV * opaque;
    char * buffer;
#ifdef PERL_IMPLICIT_SYS
    HANDLE Port; /* not owned here, the MY_CXT var is the owner of the IOCP */
#endif
    DWORD PendingWaiters; /* undelivered active IOCPs containing this APROC * */
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
    cxt->Port =
    CreateIoCompletionPort(
        INVALID_HANDLE_VALUE,
        NULL,
        0,
        1 /* 1 thread, Perl doesn't process TAP with many to many layout */
    );
    DBGCHKBOOL(cxt->Port);
}

#ifdef NOTIFY_ON_PROC_END
/* turns a WFSO/WFMO event (process exit in this case) into an IOCP queue event */
/* reads are more likely to happen then process exits*/
VOID CALLBACK WaitFunc( APROC * aproc, BOOLEAN TimerOrWaitFired) {

    if(TimerOrWaitFired == TRUE)
        DebugBreak();

#ifdef PERL_IMPLICIT_SYS
    DBGCHKBOOL(PostQueuedCompletionStatus(
        aproc->Port,
        0,
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
}

#endif /* #ifdef NOTIFY_ON_PROC_END */


void
StartRead(APROC * aproc) {
    BOOL ret;
    DWORD err;
    aproc->PendingWaiters++;
#ifdef DBGAPIPE
    if(aproc->buffer)
        DebugBreak();
#endif
    Newx(aproc->buffer, PIPE_BUF_SIZE+1, char);
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
                DebugBreak(); /* unknown ATM how to convert win32 err code to
                                aproc->overlapped.Internal NTSTATUS, StartRead
                                will probably have to use NtReadFile to get the
                                real NTSTATUS code */
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
        DWORD start = GetTickCount();
        DWORD end;
        ret = UnregisterWait(aproc->hWaitObj);
        end = GetTickCount();
/* this isn't supposed to block, but GTC is a low res counter remember */
        if(end - start > 20)
            DebugBreak();
/* ERROR_IO_PENDING is not acceptable, the callback was supposed to be 1 shot */
        DBGCHKBOOL(ret);
        DBGSETNULL(aproc->hWaitObj);
    }
#endif
    SvREFCNT_dec_NN(aproc->opaque);
    DBGSETNULL(aproc->opaque);

#ifdef NOTIFY_ON_PROC_END
    DBGCHKBOOL(CloseHandle(aproc->hProcess));
    DBGSETNULL(aproc->hProcess);
#endif
    DBGCHKBOOL(CloseHandle(aproc->hStdOut));
    DBGSETNULL(aproc->hStdOut);
    Safefree(aproc);
}


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
run(cmd, opaque)
    char * cmd
    SV * opaque
PREINIT:
    HANDLE hWritePipe;
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
      120 * 1000, /* from MyCreatePipeEx and reactos's CreatePipe */
      NULL/*LPSECURITY_ATTRIBUTES lpSecurityAttributes*/
    );

    DBGCHKBOOL(aproc->hStdOut);
    {
        dMY_CXT;
#ifdef PERL_IMPLICIT_SYS
        /* WaitFunc needs to know what IOCP to deliver its exit event on, aTHX
           here is another choice, but remember WaitFunc is running in a random
           thread so using the interp from the wrong OS thread is risky so
           just put the IOCP here to KISS */
        aproc->Port = MY_CXT.Port;
#endif
        DBGCHKBOOL(CreateIoCompletionPort(
          aproc->hStdOut,
          MY_CXT.Port,
          KEY_READ_FINISHED,
          0 /* max threads, ignored because its an existing port */
        ));
    }

    hWritePipe = CreateFileW(
                        PipeName,
                        GENERIC_WRITE,
                        0,
                        (LPSECURITY_ATTRIBUTES)&WritePipeAttributes,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, /* b88 added overlapped, remove? */
                        NULL
                      );
#ifdef DBGAPIPE
    if (INVALID_HANDLE_VALUE == hWritePipe)
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
    /* this needs a critical section for thread safety, or use create suspended
        and DuplicateHandle and WriteProcessMemory to new proc's PEB's
        _RTL_USER_PROCESS_PARAMETERS->StandardOutput and friends like CreateProcess
        does internally, Perl had problems with this/dup() in the past, where the
        effects show up in other ithreads/psuedoprocs */
    SetStdHandle(STD_OUTPUT_HANDLE, hWritePipe);
#endif
#ifdef INHERIT_HANDLES
    StartupInfo.cb = sizeof(StartupInfo);
    memset(&StartupInfo.lpReserved, 0, offsetof(STARTUPINFO,hStdInput)-offsetof(STARTUPINFO,lpReserved));
    StartupInfo.dwFlags = STARTF_USESTDHANDLES; /* egh zeroed by the memset */
    StartupInfo.hStdInput	= (HANDLE)_get_osfhandle(0);
    StartupInfo.hStdOutput = hWritePipe;
    StartupInfo.hStdError	= (HANDLE)_get_osfhandle(2);
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
#endif
    DBGCHKBOOL(CloseHandle(hWritePipe));
    } /* scope CreateProcess */
    if(RETVAL == ERROR_SUCCESS) {
#ifdef NOTIFY_ON_PROC_END
        DBGCHKBOOL(RegisterWaitForSingleObject(
            &aproc->hWaitObj,
            aproc->hProcess,
            WaitFunc,
            aproc,
            INFINITE,
            WT_EXECUTEONLYONCE));
        aproc->PendingWaiters++;
#endif
        /* save the caller's opaque SV*, this is probably an RV to a blessed SV */
        aproc->opaque = SvREFCNT_inc_simple_NN(opaque);
        StartRead(aproc);
    } else {
        DBGCHKBOOL(CloseHandle(aproc->hStdOut));
        aproc->hStdOut = NULL;
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
    DWORD NumberOfBytes;
    ULONG_PTR CompletionKey;
    APROC * aproc;
    BOOL ret;
CODE:
{   /* use CODE: so SP isn't moved back so the SETs below works */
    ret = GetQueuedCompletionStatus(
        MY_CXT.Port,
        &NumberOfBytes,
        &CompletionKey,
        (LPOVERLAPPED*)&aproc,
        INFINITE
    );
    /* a serious error happened, no packet received */
    if(ret == FALSE && aproc == NULL) {
        DebugBreak();
    }
    SvREFCNT_inc_simple_NN(aproc->opaque);
    /* 1 scalar in, 1 scalar out, so use SETs with no PUTBACK since SP didn't move */
    SETs(sv_2mortal(aproc->opaque));
    /* SP can be reused by CC optimizer after here */
    if(CompletionKey == KEY_READ_FINISHED) {
        aproc->PendingWaiters--;
        /* note here, NumberOfBytes might be less than PIPE_BUF_SIZE, so we are
          undershooting the real length of the mem block, a realloc that returns
          the same ptr might happen, I dont see any way around it */
        /* not using GetOverlappedResult, dont need its features/bloat */
        /* 0xC000014B 3221225803  STATUS_PIPE_BROKEN */
        if(NT_SUCCESS(aproc->overlapped.Internal)
           || aproc->overlapped.Internal == STATUS_PIPE_BROKEN ) {
            char * buffer = aproc->buffer;
            aproc->buffer = NULL; /* rmv later */
            buffer[NumberOfBytes] = '\0';
#ifdef STATS
            /* exclude 0 byte reads, they are in-band "signalling" I/O, not data */
            if(NumberOfBytes) {
                MY_CXT.MinRead = min(MY_CXT.MinRead, NumberOfBytes);
                MY_CXT.MaxRead = max(MY_CXT.MaxRead, NumberOfBytes);
                MY_CXT.AvgRead = (MY_CXT.AvgRead+NumberOfBytes)/2.0;
            }
#endif
            sv_usepvn_flags(bufferSV, buffer, NumberOfBytes, SV_HAS_TRAILING_NUL);
            /* a 0 byte read means end of stream */
#ifdef DBGAPIPE
            /*  STATUS_PIPE_BROKEN is end of stream, not STATUS_SUCCESS
                investigate if this trips */
            if(NT_SUCCESS(aproc->overlapped.Internal) && NumberOfBytes == 0)
                DebugBreak();
#endif
            if(NumberOfBytes)
                StartRead(aproc);
            else
                FreeAPROC(aTHX_ aproc);
        }
        else
            DebugBreak(); /* unknown error happened on the async read */
    }
#ifdef NOTIFY_ON_PROC_END
    else if (CompletionKey == KEY_PROCESS_EXITED) {
        aproc->PendingWaiters--;
        FreeAPROC(aTHX_ aproc);
    }
#endif
#ifdef DBGAPIPE
    else /* unknown completion key */
        DebugBreak();
#endif
    return; /* skip implicit PUTBACK */
}