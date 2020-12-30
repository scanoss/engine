#ifndef __SNIPPETS_H
    #define __SNIPPETS_H

#include "scanoss.h"
bool skip_snippets(char *src, uint64_t srcln);
uint32_t compile_ranges(uint8_t *matchmap_matching, char *ranges, char *oss_ranges);

#endif
