#ifndef __MATCH_H
    #define __MATCH_H

#include "scanoss.h"

void flip_slashes(char *data);
void output_matches_json(match_data *matches, scan_data *scan_ptr);
match_data *compile_matches(scan_data *scan);
match_data *load_matches(scan_data *scan);
void add_match(int position, match_data match, match_data *matches);
match_data fill_match(uint8_t *url_key, char *file_path, uint8_t *url_record);

#endif
