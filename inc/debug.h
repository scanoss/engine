#ifndef __DEBUG_H
    #define __DEBUG_H
    
#include <stdint.h>
#include <stdbool.h>
#include "scanoss.h"
#include "scan.h"

extern bool debug_on; //= false; //set debug mode from main.
extern bool quiet;


void scanlog(const char *fmt, ...);
void map_dump(scan_data_t *scan);
long microseconds_now(void);
void scan_benchmark(void);
void slow_query_log(scan_data_t *scan);


#endif
