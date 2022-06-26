#ifndef __RANK_H
    #define __RANK_H

#include "scanoss.h"


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
long component_age(char *vendor, char *component);
len_rank *load_path_rank(file_recordset *files, int records);
void dump_path_rank(len_rank *path_rank, file_recordset *files);
void init_path_ranking(path_ranking *path_rank);
#endif
