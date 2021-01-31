#ifndef __SCANOSS_H
    #define __SCANOSS_H
    
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MD5_LEN 16
#define WFP_LN 4
#define WFP_REC_LN 18
#define MATCHMAP_RANGES 10
#define MAX_FILE_PATH 1024
#define FETCH_MAX_FILES 20000
#define MAX_FIELD_LN 64

#define SCAN_LOG "/tmp/scanoss_scan.log"
#define MAP_DUMP "/tmp/scanoss_map.dump"
#define SLOW_QUERY_LOG "/tmp/scanoss_slow_query.log"

extern char SCANOSS_VERSION[7];

typedef enum {none, component, file, snippet} matchtype;
typedef enum {plain, cyclonedx, spdx, spdx_xml} output_format;
extern const char *matchtypes[];// = {"none", "component", "file", "snippet"};
extern const char *license_sources[];// = {"component_declared", "file_spdx_tag", "file_header"};
extern const char *copyright_sources[];// = {"component_declared", "file_header"};
extern const char *vulnerability_sources[];// = {"nvd", "github_advisories"};
extern const char *quality_sources[];// = {"best_practices"};
extern const char *dependency_sources[];// = {"component_declared"};

typedef struct keywords
{
	int  count;
	char word[MAX_FIELD_LN];
} keywords;

typedef struct matchmap_range
{
	uint16_t from;
	uint16_t to;
	uint16_t oss_line;
} matchmap_range;

typedef struct matchmap_entry
{
	uint8_t md5[MD5_LEN];
	uint16_t hits;
	matchmap_range range[MATCHMAP_RANGES];
	uint8_t lastwfp[WFP_LN];
} matchmap_entry;

typedef struct file_recordset
{
	uint8_t component_id[MD5_LEN];
	char path[MAX_FILE_PATH];
	int path_ln;
	bool external;
} file_recordset;

typedef struct scan_data
{
	uint8_t *md5;
	char *file_path;
	char *file_size;
	char source_md5[MD5_LEN * 2 + 1];
	uint32_t *hashes;
	uint32_t *lines;
	uint32_t hash_count;
	long timer;
	bool preload;
	int total_lines;
	matchtype match_type;
	matchmap_entry *matchmap;
	uint32_t matchmap_size;
} scan_data;

typedef struct match_data
{
	matchtype type;
	char lines[MAX_FIELD_LN * 2];
	char oss_lines[MAX_FIELD_LN * 2];
	char vendor[MAX_FIELD_LN];
	char component[MAX_FIELD_LN];
	char version[MAX_FIELD_LN];
	char latest_version[MAX_FIELD_LN];
	char url[MAX_FILE_PATH];
	char file[MAX_FILE_PATH];
	int  path_ln;
	char license[MAX_FIELD_LN];
	char matched[MAX_FIELD_LN];
	uint8_t file_md5[MD5_LEN];
	uint8_t component_md5[MD5_LEN];
	uint8_t pair_md5[MD5_LEN];
	int vulnerabilities;
	bool selected;
	bool snippet_to_component;
	scan_data *scandata;
} match_data;

/* Component ranking for evaluating /external/ paths */
typedef struct component_name_rank
{
	char vendor[MAX_FIELD_LN];
	char component[MAX_FIELD_LN];
	uint8_t component_id[MD5_LEN];
	char component_record[MAX_FILE_PATH];
	char file[MAX_FILE_PATH];
	long score;
} component_name_rank;

/* Path ranking when looking for shortest paths / component age */
typedef struct path_ranking
{
	int pathid;
	long score; // Score will store path length or component age
	char component[MAX_FIELD_LN];
	char vendor[MAX_FIELD_LN];
} path_ranking;

unsigned char *linemap;
unsigned char *map;
int map_rec_len;
extern bool match_extensions;// = false;
extern int report_format;// = plain;

/* Vendor and component hint hold the last component matched/guessed */
char vendor_hint[MAX_FIELD_LN];
char component_hint[MAX_FIELD_LN];

#include "ldb.h"

/* DB tables */
struct ldb_table oss_component;
struct ldb_table oss_file;
struct ldb_table oss_wfp;

extern bool first_file;
extern int max_vulnerabilities;

extern char *sbom;
extern char *blacklisted_assets;

/* Prototype declarations */
int wfp_scan(scan_data *scan);
bool ldb_scan(scan_data *scan);
matchtype ldb_scan_snippets(scan_data *scan_ptr);
bool key_find(uint8_t *rs, uint32_t rs_len, uint8_t *subkey, uint8_t subkey_ln);
void recurse_directory (char *path);
match_data match_init();
bool blacklist_match(uint8_t *component_record);
void ldb_get_first_record(struct ldb_table table, uint8_t* key, void *void_ptr);
void scan_data_free(scan_data scan);
int count_matches(match_data *matches);
bool component_hint_matches_path(file_recordset *files, int records, char *component_hint);
void external_component_hint_in_path(file_recordset *files, int records, char *hint, component_name_rank *component_rank);
void select_best_component_from_rank(component_name_rank *component_rank, char *component_hint);
void add_files_to_matches(\
		file_recordset *files,\
		int records,\
		char *component_hint,\
		uint8_t *file_md5,\
		match_data *matches);
bool component_hint_from_shortest_paths(file_recordset *files, int records, char *hint1, char *hint2, component_name_rank *component_rank, path_ranking *path_rank);
void consider_file_record(\
		uint8_t *component_id,\
		char *path,\
		match_data *matches,\
		char *component_hint,\
		uint8_t *matching_md5);
int seek_component_hint_in_path(\
		file_recordset *files,\
		int records,\
		char *hint,\
		component_name_rank *component_rank);
void init_path_ranking(path_ranking *path_rank);
bool select_best_match(match_data *matches);

#endif
