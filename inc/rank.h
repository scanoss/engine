#ifndef __RANK_H
    #define __RANK_H

#include "scanoss.h"
/* Component ranking for evaluating /external/ paths */
typedef struct component_name_rank
{
	char vendor[MAX_FIELD_LN];
	char component[MAX_FIELD_LN];
	char purl[MAX_FILE_PATH];
	uint8_t url_id[MD5_LEN];
	uint8_t purl_md5[MD5_LEN];
	char url_record[MAX_FILE_PATH];
	char file[MAX_FILE_PATH];
	long score;
	long age;
} component_name_rank;

/* Path ranking when looking for shortest paths / component age */
typedef struct path_ranking
{
	int pathid;
	long score; // Score will store path length or component age
	char component[MAX_FIELD_LN];
	char vendor[MAX_FIELD_LN];
	char purl[MAX_FILE_PATH];
	uint8_t purl_md5[MD5_LEN];
} path_ranking;

int get_component_age(uint8_t *md5);
bool component_hint_matches_path(file_recordset *files, int records, char *component_hint);
void external_component_hint_in_path(file_recordset *files, int records, char *hint, component_name_rank *component_rank);
void select_best_component_from_rank(component_name_rank *component_rank, char *component_hint);

int fill_component_age(component_name_rank *component_rank);
long component_age(char *vendor, char *component);
component_name_rank shortest_paths_check(file_recordset *files, int records);
len_rank *load_path_rank(file_recordset *files, int records);
void dump_path_rank(len_rank *path_rank, file_recordset *files);
void init_path_ranking(path_ranking *path_rank);
#endif
