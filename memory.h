#ifndef MEMORY_H
#define MEMORY_H

#include <stdint.h>

#define likely(x)	 __builtin_expect(!!(x), 1) 
#define unlikely(x) __builtin_expect(!!(x), 0) 

typedef uint8_t u8;

#endif
