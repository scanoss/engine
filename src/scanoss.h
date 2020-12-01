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

#define SCAN_LOG "/tmp/scanoss_scan.log"
#define MAP_DUMP "/tmp/scanoss_map.dump"
#define SLOW_QUERY_LOG "/tmp/scanoss_slow_query.log"

char SCANOSS_VERSION[7] = "4.0.2";

typedef enum { none, component, file, snippet } matchtype;
typedef enum { plain, cyclonedx, spdx } report_format;
const char *matchtypes[] = {"none", "component", "file", "snippet"};
const char *license_sources[] = {"component_declared", "file_spdx_tag", "file_header"};
const char *copyright_sources[] = {"component_declared", "file_header"};
const char *vulnerability_sources[] = {"nvd", "github_advisories"};
const char *quality_sources[] = {"best_practices"};
const char *dependency_sources[] = {"component_declared"};

typedef struct keywords
{
	int  count;
	char word[128];
} keywords;

typedef struct scan_data
{
	uint8_t *md5;
	char *file_path;
	char *file_size;
	uint32_t *hashes;
	uint32_t *lines;
	uint32_t hash_count;
	long timer;
	bool preload;
	int total_lines;
	matchtype match_type;
	uint8_t *matchmap;
	uint64_t matchmap_ptr;
} scan_data;

typedef struct match_data
{
	matchtype type;
	char lines[128];
	char oss_lines[128];
	char vendor[64];
	char component[64];
	char version[64];
	char latest_version[64];
	char url[1024];
	char file[4096];
	int  path_ln;
	char license[64];
	char matched[64];
	uint8_t file_md5[16];
	uint8_t component_md5[16];
	uint8_t pair_md5[16];
	int vulnerabilities;
	bool selected;
	bool snippet_to_component;
	scan_data *scandata;
} match_data;

unsigned char *linemap;
unsigned char *map;
int map_rec_len;
bool debug_on = false;
bool quiet = false;
bool match_extensions = false;
int json_format = plain;

#include "external/wfp/winnowing.c"
#include "external/ldb/ldb.h"

/* DB tables */
struct ldb_table oss_component;
struct ldb_table oss_file;
struct ldb_table oss_wfp;

bool first_file = true;

char *sbom = NULL;
char *blacklisted_assets = NULL;

/* Prototype declarations */
int wfp_scan(char *path);
bool ldb_scan(scan_data *scan);
matchtype ldb_scan_snippets(scan_data *scan_ptr);
bool key_find(uint8_t *rs, uint32_t rs_len, uint8_t *subkey, uint8_t subkey_ln);
void recurse_directory (char *path);
match_data match_init();
void extract_csv(char *out, char *in, int n, long limit);
bool blacklist_match(uint8_t *component_record);
void extract_csv(char *out, char *in, int n, long limit);
void ldb_get_first_record(struct ldb_table table, uint8_t* key, void *void_ptr);
scan_data scan_data_init();
void scan_data_free(scan_data scan);
int count_matches(match_data *matches);
