#include <windows.h>
#include <stdio.h>

#include "xor_strings.h"

#define BUFSIZE 512

static DWORD WINAPI InstanceThread(LPVOID);
static void AppOutput(LPSTR fmt, ...);

int main(int argc, char** argv)
{
    BOOL   fConnected = FALSE;
    DWORD  dwThreadId = 0;
    HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL;
    LPCSTR lpszPipename = MILLER_MSGPIPE;

    (void)argc;
    (void)argv;

    // The main loop creates an instance of the named pipe and
    // then waits for a client to connect to it. When the client
    // connects, a thread is created to handle communications
    // with that client, and this loop is free to wait for the
    // next client connect request. It is an infinite loop.

    for (;;) {
        AppOutput("Pipe Server: Main thread awaiting client connection on %s", lpszPipename);
        hPipe = CreateNamedPipe(
            lpszPipename,             // pipe name
            PIPE_ACCESS_DUPLEX,       // read/write access
            PIPE_TYPE_MESSAGE |       // message type pipe
            PIPE_READMODE_MESSAGE |   // message-read mode
            PIPE_WAIT,                // blocking mode
            PIPE_UNLIMITED_INSTANCES, // max. instances
            BUFSIZE,                  // output buffer size
            BUFSIZE,                  // input buffer size
            0,                        // client time-out
            NULL);                    // default security attribute
        if (hPipe == INVALID_HANDLE_VALUE) {
            AppOutput("CreateNamedPipe failed (ERROR: %lu).", GetLastError());
            return -1;
        }
        // Wait for the client to connect; if it succeeds,
        // the function returns a nonzero value. If the function
        // returns zero, GetLastError returns ERROR_PIPE_CONNECTED.
        fConnected = ConnectNamedPipe(hPipe, NULL) ?
           TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (fConnected) {
            AppOutput("Client connected, creating a processing thread.");
            // Create a thread for this client.
            hThread = CreateThread(
                NULL,              // no security attribute
                0,                 // default stack size
                InstanceThread,    // thread proc
                (LPVOID) hPipe,    // thread parameter
                0,                 // not suspended
                &dwThreadId);      // returns thread ID

            if (hThread == NULL) {
                AppOutput("CreateThread failed (ERROR: %lu).", GetLastError());
                return -1;
            } else CloseHandle(hThread);
        } else {
            // The client could not connect, so close the pipe.
            CloseHandle(hPipe);
        }
    }

    return 0;
}

DWORD WINAPI InstanceThread(LPVOID lpvParam)
// This routine is a thread processing function to read from and reply to a client
// via the open pipe connection passed from the main loop. Note this allows
// the main loop to continue executing, potentially creating more threads of
// of this procedure to run concurrently, depending on the number of incoming
// client connections.
{
    HANDLE hHeap      = GetProcessHeap();
    char* pchRequest = (char*)HeapAlloc(hHeap, 0, BUFSIZE*sizeof(char));
    char* pchReply   = (char*)HeapAlloc(hHeap, 0, BUFSIZE*sizeof(char));
    DWORD cbBytesRead = 0;
    BOOL fSuccess = FALSE;
    HANDLE hPipe  = NULL;

    // Do some extra error checking since the app will keep running even if this
    // thread fails.
    if (lpvParam == NULL) {
        AppOutput("ERROR - Pipe Server Failure");
        if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
        if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
        return (DWORD)-1;
    }
    if (pchRequest == NULL) {
        AppOutput("ERROR - Pipe Server Failure");
        if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
        return (DWORD)-1;
    }
    if (pchReply == NULL) {
        AppOutput("ERROR - Pipe Server Failure");
        if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
        return (DWORD)-1;
    }

    // Print verbose messages. In production code, this should be for debugging only.
    AppOutput("InstanceThread created, receiving and processing messages.");
    // The thread's parameter is a handle to a pipe object instance.
    hPipe = (HANDLE) lpvParam;
    // Loop until done reading
    while (1) {
        // Read client requests from the pipe. This simplistic code only allows messages
        // up to BUFSIZE characters in length.
        fSuccess = ReadFile(
            hPipe,        // handle to pipe
            pchRequest,   // buffer to receive data
            BUFSIZE*sizeof(char), // size of buffer
            &cbBytesRead, // number of bytes read
            NULL);        // not overlapped I/O

        if (!fSuccess || cbBytesRead == 0) {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                AppOutput("InstanceThread: client disconnected (ERROR: %lu).", GetLastError());
            } else {
                AppOutput("InstanceThread ReadFile failed (ERROR: %lu).", GetLastError());
            }
            break;
        }
        // Process the incoming message.
        AppOutput("--- MESSAGE ---");
        if (pchRequest[cbBytesRead-1] == '\n') {
            pchRequest[cbBytesRead-1] = '\0';
        }
        printf("\"%.*s\"\n", (int)cbBytesRead, pchRequest);
        memset(pchRequest, '\0', BUFSIZE*sizeof(char));
    }

    // Flush the pipe to allow the client to read the pipe's contents
    // before disconnecting. Then disconnect the pipe, and close the
    // handle to this pipe instance.
    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    HeapFree(hHeap, 0, pchRequest);
    HeapFree(hHeap, 0, pchReply);
    AppOutput("InstanceThread exitting.");
    return 1;
}

static void AppOutput(LPSTR fmt, ...)
{
    char* pBuffer = NULL;
    SYSTEMTIME stm;
    GetSystemTime(&stm);

    va_list args = NULL;
    va_start(args, fmt);

    vasprintf(&pBuffer, fmt, args);
    printf("[%02d-%02d-%02d]: %s\n", stm.wHour, stm.wMinute, stm.wSecond, pBuffer);
    free(pBuffer);

    va_end(args);
}
