#pragma once
#include <windows.h>

/*BOF Defs*/
#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define memset MSVCRT$memset

//MSVCRT
WINBASEAPI int __cdecl MSVCRT$memcmp(const void *buffer1, const void *buffer2, size_t count);
WINBASEAPI void __cdecl MSVCRT$memset(void* dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$strncmp(const char *string1, const char *string2, size_t count);
WINBASEAPI SIZE_T WINAPI MSVCRT$strlen(const char* str);
WINBASEAPI int __cdecl MSVCRT$_snprintf(char* s, size_t n, const char* fmt, ...);
//KERNEL32
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);