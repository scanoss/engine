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
#define MIN_FILE_SIZE 256 // files below this size will be ignored
#define MAX_SNIPPET_IDS_RETURNED 10000
#define CRC_LIST_LEN 256 // list of crc checksums to avoid metadata duplicates

/* Log files */
#define SCAN_LOG "/tmp/scanoss_scan.log"
#define MAP_DUMP "/tmp/scanoss_map.dump"
#define SLOW_QUERY_LOG "/tmp/scanoss_slow_query.log"

#define API_URL "https://osskb.org/api"
#define DEFAULT_OSS_DB_NAME "oss"

/* Engine configuration flags */
#define ENGINE_FLAGS_FILE "/var/lib/scanoss/etc/flags"
#define DISABLE_SNIPPET_MATCHING 1
#define ENABLE_SNIPPET_IDS 2
#define DISABLE_DEPENDENCIES 4
#define DISABLE_LICENSES 8
#define DISABLE_COPYRIGHTS 16
#define DISABLE_VULNERABILITIES 32
#define DISABLE_QUALITY 64
#define DISABLE_CRIPTOGRAPHY 128
#define DISABLE_BEST_MATCH 256
#define ENABLE_REPORT_IDENTIFIED 512
#define ENABLE_DOWNLOAD_URL 1024
#define MAX_PURLS 10
#define SHORTEST_PATHS_QTY 50 // number of shortest path to evaluate

extern uint64_t engine_flags;

extern char SCANOSS_VERSION[7];

typedef enum {none, url, file, snippet} matchtype;
extern const char *matchtypes[];
extern const char *license_sources[];
extern const char *copyright_sources[];
extern const char *vulnerability_sources[];
extern const char *quality_sources[];
extern const char *dependency_sources[];

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
	uint8_t url_id[MD5_LEN];
	char path[MAX_FILE_PATH];
	int path_ln;
	bool external;
} file_recordset;

typedef struct len_rank
{
	int id;
	int len;
} len_rank;

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
	char line_ranges[MAX_FIELD_LN * 2];
	char oss_ranges[MAX_FIELD_LN * 2];
	uint8_t *match_ptr; // pointer to matching record in match_map
	/* comma separated list of matching snippet ids */
	char snippet_ids[MAX_SNIPPET_IDS_RETURNED * WFP_LN * 2 + MATCHMAP_RANGES + 1];
	char matched_percent[MAX_FIELD_LN];
	bool identified;
} scan_data;

typedef struct match_data
{
	matchtype type;
	char vendor[MAX_FIELD_LN];
	char component[MAX_FIELD_LN];
	char version[MAX_FIELD_LN];
	char release_date[MAX_FIELD_LN];
	char latest_version[MAX_FIELD_LN];
	char main_url[MAX_FILE_PATH];
	char license[MAX_FIELD_LN];
	char url[MAX_FILE_PATH];
	char file[MAX_FILE_PATH];
	int  path_ln;
	uint8_t file_md5[MD5_LEN];
	uint8_t url_md5[MD5_LEN];
	uint8_t pair_md5[MD5_LEN]; // DEPRECATED

	/* PURL array */
	char purl[MAX_PURLS][MAX_FIELD_LN + 1];
	uint8_t purl_md5[MAX_PURLS][MD5_LEN];

	uint32_t crclist[CRC_LIST_LEN];
	int vulnerabilities;
	bool selected;
	bool first_record;
	bool snippet_to_component;
	scan_data *scandata;
} match_data;

typedef struct release_version
{
	char version[MAX_FIELD_LN];
	char date[MAX_FIELD_LN];
	uint8_t url_id[MAX_FIELD_LN];
} release_version;

/* Component ranking for evaluating /external/ paths */
typedef struct component_name_rank
{
	char vendor[MAX_FIELD_LN];
	char component[MAX_FIELD_LN];
	char purl[MAX_FIELD_LN];
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
	char purl[MAX_FIELD_LN];
	uint8_t purl_md5[MD5_LEN];
} path_ranking;

long microseconds_start;
unsigned char *linemap;
unsigned char *map;
int map_rec_len;
extern bool match_extensions;// = false;

/* File tracing -qi */
uint8_t trace_id[MD5_LEN];
bool trace_on;

/* Vendor and component hint hold the last component matched/guessed */
char vendor_hint[MAX_FIELD_LN];
char component_hint[MAX_FIELD_LN];

#include "ldb.h"

/* DB tables */
struct ldb_table oss_url;
struct ldb_table oss_file;
struct ldb_table oss_wfp;
struct ldb_table oss_purl;
struct ldb_table oss_copyright;
struct ldb_table oss_quality;
struct ldb_table oss_vulnerability;
struct ldb_table oss_dependency;
struct ldb_table oss_license;
struct ldb_table oss_attribution;
struct ldb_table oss_cryptography;

extern bool first_file;
extern int max_vulnerabilities;

extern char *sbom;
extern char *ignored_assets;

/* Prototype declarations */
int wfp_scan(scan_data *scan);
void ldb_scan(scan_data *scan);
matchtype ldb_scan_snippets(scan_data *scan_ptr);
bool key_find(uint8_t *rs, uint32_t rs_len, uint8_t *subkey, uint8_t subkey_ln);
void recurse_directory (char *path);
match_data match_init();
bool ignored_asset_match(uint8_t *url_record);
void ldb_get_first_record(struct ldb_table table, uint8_t* key, void *void_ptr);
void scan_data_free(scan_data scan);
int count_matches(match_data *matches);
bool component_hint_matches_path(file_recordset *files, int records, char *component_hint);
void external_component_hint_in_path(file_recordset *files, int records, char *hint, component_name_rank *component_rank);
void select_best_component_from_rank(component_name_rank *component_rank, char *component_hint);
bool component_hint_from_shortest_paths(file_recordset *files, int records, char *hint1, char *hint2, component_name_rank *component_rank, path_ranking *path_rank);
void consider_file_record(\
		uint8_t *component_id,\
		char *path,\
		match_data *matches,\
		char *component_hint,\
		uint8_t *match_md5);
int seek_component_hint_in_path(\
		file_recordset *files,\
		int records,\
		char *hint,\
		component_name_rank *component_rank);
void init_path_ranking(path_ranking *path_rank);
bool select_best_match(match_data *matches);
void mz_file_contents(char *key);
void print_attribution_notices(match_data match);

#endif
