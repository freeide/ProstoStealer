#pragma once
void *_alloc(SIZE_T size);
void _free(void *mem);
void _copy(void *dst, const void *src, SIZE_T size);
void _set(void *mem, char c, SIZE_T size);
void _zero(void *mem, SIZE_T size);
int _cmp(const void *m1, const void *m2, SIZE_T size);