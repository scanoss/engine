#ifndef __DEBUG_H
    #define __DEBUG_H
    
#include <stdint.h>
#include <stdbool.h>
#include "scanoss.h"


bool debug_on; //= false; //set debug mode from main.
bool quiet;


void scanlog(const char *fmt, ...);
void map_dump(uint8_t *mmap, uint64_t mmap_ptr) ;    
long microseconds_now(void);
void scan_benchmark(void);
void slow_query_log(scan_data scan);


#endif