#ifndef __SCAN_H
    #define __SCAN_H

#include "scanoss.h"

scan_data scan_data_init();
char *parse_sbom(char *filepath, bool load_vendor);
uint8_t *biggest_snippet(scan_data *scan);
int get_component_age(uint8_t *md5);
void consider_file_record(\
		uint8_t *component_id,\
		char *path,\
		match_data *matches,\
		char *component_hint,\
		uint8_t *matching_md5);

#endif
