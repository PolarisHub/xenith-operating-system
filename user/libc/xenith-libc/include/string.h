#ifndef XENITH_STRING_H
#define XENITH_STRING_H
#include <stddef.h>
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *left, const void *right, size_t n);
size_t strlen(const char *value);
#endif
