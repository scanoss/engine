#ifndef __SNIPPETS_H
    #define __SNIPPETS_H

#include "scanoss.h"
bool skip_snippets(char *src, uint64_t srcln);
uint32_t compile_ranges(scan_data *scan);
uint8_t *biggest_snippet(scan_data *scan);

#endif
