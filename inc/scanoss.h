#ifndef __SCANOSS_H
#define __SCANOSS_H
    
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
#include "limits.h"

#define MAX_FILE_PATH 1024
#define FETCH_MAX_FILES 12000
#define MIN_FILE_SIZE 256 // files below this size will be ignored
#define CRC_LIST_LEN 1024 // list of crc checksums to avoid metadata duplicates
#define SNIPPET_LINE_TOLERANCE 10

#define WFP_LN 4
#define WFP_REC_LN 18

/* Log files */
#define SCANOSS_VERSION "5.4.8"
#define SCAN_LOG "/tmp/scanoss_scan.log"
#define MAP_DUMP "/tmp/scanoss_map.dump"
#define SLOW_QUERY_LOG "/tmp/scanoss_slow_query.log"

#define API_URL "https://api.osskb.org"
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
#define DISABLE_REPORT_IDENTIFIED 512
#define ENABLE_DOWNLOAD_URL 1024
#define ENABLE_PATH_HINT 2048
#define DISABLE_SERVER_INFO 4096
#define DISABLE_HEALTH 8192
#define ENABLE_HIGH_ACCURACY 16384

#define MAX_SBOM_ITEMS 2000
#define SHORTEST_PATHS_QTY 4000 // number of shortest path to evaluate

#define MD5_LEN 16
#define MAX_PURLS 10
#define MAX_FIELD_LN 1024

extern uint64_t engine_flags;

extern const char *matchtypes[];
extern const char *license_sources[];
extern const char *copyright_sources[];
extern const char *vulnerability_sources[];
extern const char *quality_sources[];
extern const char *dependency_sources[];

typedef enum {MATCH_NONE, MATCH_FILE, MATCH_SNIPPET, MATCH_BINARY} match_t;

typedef struct keywords
{
	int  count;
	char word[MAX_FIELD_LN];
} keywords;


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

typedef struct component_item
{
	char * vendor;
	char * component;
	char * purl;
	char * version;
	char * license;
} component_item;


extern long microseconds_start;
extern int map_rec_len;
extern bool match_extensions;

/*component hint hold the last component matched/guessed */
extern char * component_hint;

#include "ldb.h"

/* DB tables */
extern struct ldb_table oss_url;
extern struct ldb_table oss_file;
extern struct ldb_table oss_wfp;
extern struct ldb_table oss_purl;
extern struct ldb_table oss_copyright;
extern struct ldb_table oss_quality;
extern struct ldb_table oss_vulnerability;
extern struct ldb_table oss_dependency;
extern struct ldb_table oss_license;
extern struct ldb_table oss_attribution;
extern struct ldb_table oss_cryptography;
extern struct ldb_table oss_sources;
extern struct ldb_table oss_notices;


extern bool first_file;
extern int max_vulnerabilities;

extern char *ignored_assets;
extern component_item *ignore_components;
extern component_item *declared_components;


/* Prototype declarations */

bool key_find(uint8_t *rs, uint32_t rs_len, uint8_t *subkey, uint8_t subkey_ln);
void recurse_directory (char *path);

bool ignored_asset_match(uint8_t *url_record);
void ldb_get_first_record(struct ldb_table table, uint8_t* key, void *void_ptr);

int binary_scan(char * bfp);
#endif
