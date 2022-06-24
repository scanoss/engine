#ifndef __MATCH_LIST_H
#define __MATCH_LIST_H
#include <stdint.h>
#include <sys/queue.h>
#include <stdbool.h>

#define MD5_LEN 16
#define MAX_PURLS 10
#define MAX_FIELD_LN 1024


typedef enum {MATCH_NONE, MATCH_URL, MATCH_FILE, MATCH_SNIPPET} match_t;
typedef struct match_data_t match_data_t;
typedef struct scan_data_t scan_data_t;
typedef struct component_data_t
{
	char * vendor;
	char * component;
	char * version;
	char * release_date;
	char * latest_release_date;
	char * latest_version;
	char * license;
	char * url;
	char * file;	
	char * main_url;
	/* PURL array */
	char *purls[MAX_PURLS];
	uint8_t *purls_md5[MAX_PURLS];
	int vulnerabilities;
	bool identified;
	int path_ln;
	uint8_t url_md5[MD5_LEN];
	int age;
	bool url_match;
	uint32_t * crclist;
	uint8_t * file_md5_ref;
	char * copyright_text;
	char *license_text;
	char * vulnerabilities_text;
	char * dependency_text;
} component_data_t;

LIST_HEAD(comp_listhead, comp_entry) comp_head;
struct comp_listhead *cheadp;                 /* List head. */
struct comp_entry {
    LIST_ENTRY(comp_entry) entries;          /* List. */
    component_data_t * component;
};


typedef struct component_list_t
{
	struct comp_listhead headp;
	int items;
	int max_items;
	bool autolimit;
	match_data_t * match_ref;
} component_list_t;

typedef struct match_data_t
{
	match_t type;
    int hits;
	char * line_ranges;
	char * oss_ranges;
	char * matched_percent;
	int  path_ln;
	uint8_t file_md5[MD5_LEN];
	char source_md5[MD5_LEN * 2 + 1];
    uint8_t * matchmap_reg;
	uint8_t * snippet_ids;
	uint32_t * crclist;
	component_list_t component_list;
	char * quality_text;
	char * crytography_text;
} match_data_t;

LIST_HEAD(listhead, entry) head;
struct listhead *headp;                 /* List head. */
struct entry {
    LIST_ENTRY(entry) entries;          /* List. */
    match_data_t * match;
};

typedef struct match_list_t
{
	struct listhead headp;
	int items;
	int max_items;
	bool autolimit;
	scan_data_t * scan_ref;  
} match_list_t;

#define MAX_SNIPPET_IDS_RETURNED 10000
#define WFP_LN 4
#define WFP_REC_LN 18
#define MATCHMAP_RANGES 10
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

typedef struct scan_data_t
{
	uint8_t md5[MD5_LEN];
	char *file_path;
	char *file_size;
	char source_md5[MD5_LEN * 2 + 1];
	uint32_t *hashes;
	uint32_t *lines;
	uint32_t hash_count;
	long timer;
	bool preload;
	int total_lines;
	match_t match_type;
	matchmap_entry *matchmap;
	uint32_t matchmap_size;
	char line_ranges[MAX_FIELD_LN * 2];
	char oss_ranges[MAX_FIELD_LN * 2];
	uint8_t *match_ptr; // pointer to matching record in match_map
	/* comma separated list of matching snippet ids */
	char snippet_ids[MAX_SNIPPET_IDS_RETURNED * WFP_LN * 2 + MATCHMAP_RANGES + 1];
	char matched_percent[MAX_FIELD_LN];
	bool identified;
	match_list_t matches;
} scan_data_t;


void match_list_print(match_list_t * list, bool (*printer) (match_data_t * fpa), char * separator);
void match_list_debug(match_list_t * list);
bool match_list_add(match_list_t * list, match_data_t * new_match, bool (* val) (match_data_t * a, match_data_t * b), bool remove_a);
void match_list_destroy(match_list_t * list);
void match_list_init(match_list_t * list);
void match_list_process(match_list_t * list, bool (*funct_p) (match_data_t * fpa, void * fpb));
bool match_list_is_empty(match_list_t * list);

bool component_list_add(component_list_t * list, component_data_t * new_comp, bool (* val) (component_data_t * a, component_data_t * b), bool remove_a);
void component_data_free(component_data_t * data);
void component_list_print(component_list_t * list, bool (*printer) (component_data_t * fpa), char * separator);
bool component_date_comparation(component_data_t * a, component_data_t * b);
#endif