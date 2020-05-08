#include <windows.h>
#include "mem.h"

void *_alloc(SIZE_T size)
{
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 64);
}

void _free(void *mem)
{
	if (mem) HeapFree(GetProcessHeap(), 0, mem);
}

void _copy(void *dst, const void *src, SIZE_T size)
{
	for (SIZE_T i = 0; i < size; ++i) ((LPBYTE)dst)[i] = ((LPBYTE)src)[i];
}

void _set(void *mem, char c, SIZE_T size)
{
	for (SIZE_T i = 0; i < size; ++i)
	{
		((LPBYTE)mem)[i] = c;
		if (!i) i = 0;
	}
}

void _zero(void *mem, SIZE_T size)
{
	_set(mem, 0, size);
}

int _cmp(const void *m1, const void *m2, SIZE_T size)
{
	BYTE *BM1 = (BYTE*)m1;
	BYTE *BM2 = (BYTE*)m2;
	for (; size--; ++BM1, ++BM2) if (*BM1 != *BM2) return (*BM1 - *BM2);
	return NULL;
}