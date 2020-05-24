#include "compat.h"
#include "crypt_strings.h"
#include "log.h"
#include "file.h"


BOOL bOpenFile(const char* filepath, int oflags, HANDLE* hPtr)
{
    HANDLE file = _CreateFile(filepath, GENERIC_READ | ((oflags & OF_WRITEACCESS) ? GENERIC_WRITE : 0),
                      0, NULL, ((oflags & OF_CREATENEW) ? CREATE_ALWAYS : OPEN_EXISTING), FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return FALSE;
    *hPtr = file;
    return TRUE;
}

BOOL bHandleToBuf(HANDLE hFile, BYTE** bufPtr, SIZE_T* szFilePtr, SIZE_T* szReadPtr)
{
    if ( (*szFilePtr = _GetFileSize(hFile, NULL)) <= 0 ) return FALSE;
    if ( (*bufPtr = calloc(*szFilePtr, sizeof(BYTE))) == NULL ) return FALSE;
    return _ReadFile(hFile, *bufPtr, *szFilePtr, szReadPtr, NULL);
}

BOOL bFileToBuf(HANDLE hFile, BYTE** bufPtr, SIZE_T* szBufPtr)
{
    BOOL ret = FALSE;

    *bufPtr = NULL;
    *szBufPtr = 0;

    if (_SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        LOG_MARKER
        return ret;
    }
    if (hFile)
    {
        BYTE *buf;
        DWORD szFile;
        DWORD szRead;
        if (bHandleToBuf(hFile, &buf, &szFile, &szRead))
        {
            if (szFile == szRead)
            {
                *bufPtr = buf;
                *szBufPtr = szFile;
                ret = TRUE;
            }
            else if (buf != NULL)
            {
                LOG_MARKER
                free(buf);
            }
        }
        else
        {
            LOG_MARKER
        }
    }
    else
    {
        LOG_MARKER
    }
    return ret;
}

BOOL bFileNameToBuf(const char* szFullPath, BYTE** pBuf, SIZE_T* pBufSiz)
{
    HANDLE hFile = NULL;
    if (!bOpenFile(szFullPath, 0, &hFile) || hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    BOOL ret = bFileToBuf(hFile, pBuf, pBufSiz);
    _CloseHandle(hFile);
    return ret;
}

inline SIZE_T nBufToFile(HANDLE hFile, const BYTE* buf, SIZE_T szBuf)
{
    SIZE_T szWritten = 0;

    if (hFile)
    {
        if (_SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            LOG_MARKER
            return 0;
        }
        if (!_WriteFile(hFile, buf, szBuf, &szWritten, NULL))
        {
            szWritten = 0;
        }
    }
    return szWritten;
}

BOOL bBufToFileName(const char* szFullPath, int oflags, BYTE* buf, SIZE_T bufSiz)
{
    HANDLE hFile = NULL;
    if (!bOpenFile(szFullPath, oflags, &hFile) || hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    BOOL ret = nBufToFile(hFile, buf, bufSiz) == bufSiz;
    _CloseHandle(hFile);
    return ret;
}

BOOL isFileInDir(LPSTR szDirName, LPSTR szFileName)
{
    char* fullPath = COMPAT(calloc)(MAX_PATH+1, sizeof(char));
    DBUF(DIRFILE_FMT_ENUM, __fmt);

    if (COMPAT(snprintf)(fullPath, MAX_PATH+1, __fmt, szDirName, szFileName) <= 0)
        return FALSE;

    DWORD dwAttrib = _GetFileAttributes(fullPath);
    COMPAT(free)(fullPath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
          !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
