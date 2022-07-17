#ifndef __SNIPPETS_H
    #define __SNIPPETS_H

#include "scanoss.h"
#include "match_list.h"

extern int matchmap_max_files;

bool skip_snippets(char *src, uint64_t srcln);
uint32_t compile_ranges(match_data_t * match);
void biggest_snippet(scan_data_t *scan);
void clear_hits(uint8_t *match);

#endif
