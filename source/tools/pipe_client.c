#include <windows.h>
#include <stdio.h>

#include "xor_strings.h"

#define BUFSIZE 512

int main(int argc, char** argv)
{
    HANDLE hPipe;
    LPSTR  lpvMessage = "Default message from client.";
    BOOL   fSuccess = FALSE;
    DWORD  cbToWrite, cbWritten;
    LPCSTR  lpszPipename = MILLER_MSGPIPE;

    if(argc > 1) {
        lpvMessage = argv[1];
    }
 
    // Try to open a named pipe; wait for it, if necessary.
    while (1) {
        hPipe = CreateFile(
            lpszPipename,   // pipe name
            GENERIC_WRITE,
            0,              // no sharing
            NULL,           // default security attributes
            OPEN_EXISTING,  // opens existing pipe
            0,              // default attributes
            NULL);          // no template file
        // Break if the pipe handle is valid.
        if (hPipe != INVALID_HANDLE_VALUE) {
            break;
        }
        // Exit if an error other than ERROR_PIPE_BUSY occurs.
        if (GetLastError() != ERROR_PIPE_BUSY) {
            printf("Could not open pipe. (ERROR: %lu)\n", GetLastError());
            return -1;
        }
        // All pipe instances are busy, so wait for 20 seconds.
        if (!WaitNamedPipe(lpszPipename, 20000)) {
            printf("Could not open pipe: 20 second wait timed out.\n");
            return -1;
        }
    }

    printf("Pipe opened: %s\n", lpszPipename);
    // Send a message to the pipe server.
    cbToWrite = (lstrlen(lpvMessage)+1)*sizeof(char);

    char line[1024];
    size_t sent = 0;
    do {
        printf("Sending %lu byte message: \"%s\"\n", cbToWrite, lpvMessage);
        fSuccess = WriteFile( 
            hPipe,       // pipe handle
            lpvMessage,  // message
            cbToWrite,   // message length
            &cbWritten,  // bytes written
            NULL);       // not overlapped
        if (!fSuccess) {
            printf("WriteFile to pipe failed. (ERROR: %lu)\n", GetLastError());
            return -1;
        }
        sent++;
        if (argc == 1) {
            memset(&line[0], '\0', sizeof(line));
            printf("Input: ");
            if (fgets(line, sizeof(line), stdin) == NULL) {
                break;
            }
            lpvMessage = &line[0];
            cbToWrite = strnlen(lpvMessage, sizeof(line));
            if (lpvMessage[cbToWrite-1] == '\n') {
                lpvMessage[cbToWrite-1] = '\0';
                cbToWrite--;
            }
        } else break;
    } while (1);

    printf("%u messages sent to server\n", sent);
    CloseHandle(hPipe);
    return 0;
}
