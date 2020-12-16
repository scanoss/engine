#ifndef __MATCH_H
    #define __MATCH_H

#include "scanoss.h"

void flip_slashes(char *data);
void output_matches_json(match_data *matches, scan_data *scan_ptr);
#endif