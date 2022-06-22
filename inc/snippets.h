#ifndef __SNIPPETS_H
    #define __SNIPPETS_H

#include "scanoss.h"
#include "match_list.h"
bool skip_snippets(char *src, uint64_t srcln);
uint32_t compile_ranges(match_data_t * match);
match_list_t * biggest_snippet(scan_data *scan);
void clear_hits(uint8_t *match);

#endif
