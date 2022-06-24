#ifndef __MATCH_H
    #define __MATCH_H

#include "scanoss.h"
#include "match_list.h"

void flip_slashes(char *data);
void output_matches_json(scan_data_t *scan);
void compile_matches(scan_data_t *scan);
bool fill_component(component_data_t * component, uint8_t *url_key, char *file_path, uint8_t *url_record);

#endif
