#ifndef __RANK_H
    #define __RANK_H

#include "scanoss.h"

scan_data scan_data_init();
char *parse_sbom(char *filepath, bool load_vendor);
uint8_t *biggest_snippet(scan_data *scan);
int get_component_age(uint8_t *md5);
bool component_hint_matches_path(file_recordset *files, int records, char *component_hint);
void external_component_hint_in_path(file_recordset *files, int records, char *hint, component_name_rank *component_rank);
void select_best_component_from_rank(component_name_rank *component_rank, char *component_hint);
int add_files_to_matches(\
		file_recordset *files,\
		int records,\
		char *component_hint,\
		uint8_t *file_md5,\
		match_data *matches,
		bool add_all);
int seek_component_hint_in_path(\
    file_recordset *files,\
    int records,\
    char *hint,\
    component_name_rank *component_rank);
int seek_component_hint_in_path_start(\
    file_recordset *files,\
    int records,\
    component_name_rank *component_rank);
void init_path_ranking(path_ranking *path_rank);
bool select_best_match(match_data *matches);

#endif
