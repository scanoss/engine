#ifndef __MATCH_H
    #define __MATCH_H

#include "scanoss.h"
#include "match_list.h"

void flip_slashes(char *data);
void output_matches_json(match_list_t * matches, scan_data *scan_ptr);
match_list_t * compile_matches(scan_data *scan);
void add_match(int position, match_data match, match_data *matches);
bool fill_match(component_data_t * component, uint8_t *url_key, char *file_path, uint8_t *url_record);

#endif
