#ifndef FILE_H
#define FILE_H

#define OF_WRITEACCESS 1
#define OF_CREATENEW   2


BOOL bOpenFile(const char* szFullPath, int oflags, HANDLE* hPtr);

BOOL bHandleToBuf(HANDLE hFile, BYTE** bufPtr, SIZE_T* szFilePtr, SIZE_T* szReadPtr);

BOOL bFileToBuf(HANDLE hFile, BYTE** bufPtr, SIZE_T* szBufPtr);

BOOL bFileNameToBuf(const char* szFullPath, BYTE** pBuf, SIZE_T* pBufSiz);

SIZE_T nBufToFile(HANDLE hFile, const BYTE* buf, SIZE_T szBuf);

BOOL bBufToFileName(const char* szFullPath, int oflags, BYTE* buf, SIZE_T bufSiz);

BOOL isFileInDir(LPSTR szDirName, LPSTR szFileName);

#endif // FILE_H
