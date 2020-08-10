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

#define SCAN_LOG "/tmp/scan.log"
#define MAP_DUMP "/tmp/map.dump"

char SCANOSS_VERSION[7] = "3.23";

typedef enum { none, component, file, snippet } matchtype;
typedef enum {plain, cyclonedx, spdx} report_format;
char *matchtypes[] = {"none", "component", "file", "snippet"};

typedef struct keywords {
	int  count;
	char word[128];
} keywords;

typedef struct match_data {
	matchtype type;
	char lines[128];
	char oss_lines[128];
	char vendor[64];
	char component[64];
	char version[64];
	char latest_version[64];
	char url[1024];
	char file[4096];
	char license[64];
	char matched[64];
	char size[16];
	bool selected;
} match_data;

unsigned char *linemap;
unsigned char *map;
int map_rec_len;
bool debug_on = false;
int json_format = plain;

/*  Parameters */
int scan_limit=10;

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
matchtype ldb_scan_snippets(uint8_t *matchmap, uint64_t *matchmap_ptr, uint32_t *hashes, uint32_t hashcount, uint32_t* lines, long *elapsed);
bool key_find(uint8_t *rs, uint32_t rs_len, uint8_t *subkey, uint8_t subkey_ln);
int wfp_scan(char *path);
bool ldb_scan(char *root_path, char *path);
void recurse_directory (char *root_path, char *name);
match_data match_init();
void extract_csv(char *out, char *in, int n, long limit);
bool blacklist_match(uint8_t *component_record);
void extract_csv(char *out, char *in, int n, long limit);
void ldb_get_first_record(struct ldb_table table, uint8_t* key, void *void_ptr);

