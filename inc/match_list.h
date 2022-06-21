#ifndef __MATCH_LIST_H
#define __MATCH_LIST_H
#include <stdint.h>
#include "scanoss.h"
#include <sys/queue.h>

typedef enum {MATCH_NONE, MATCH_URL, MATCH_FILE, MATCH_SNIPPET} match_t;

typedef struct match_data_t
{
	match_t type;
    int hits;
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
	char * line_ranges;
	char * oss_ranges;
	char * matched_percent;
	int  path_ln;
	uint8_t file_md5[MD5_LEN];
	char source_md5[MD5_LEN * 2 + 1];
	uint8_t url_md5[MD5_LEN];
    uint8_t * matchmap_reg;

	/* PURL array */
	char *purls[MAX_PURLS];
	uint8_t *purls_md5[MAX_PURLS];
	int vulnerabilities;
	bool selected;
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
} match_list_t;


void match_list_print(match_list_t * list, bool (*printer) (match_data_t * fpa), char * separator);
void match_list_debug(match_list_t * list);
bool match_list_add(match_list_t * list, match_data_t * new_match, bool (* val) (match_data_t * a, match_data_t * b), bool remove_a);
void match_list_destroy(match_list_t * list);
match_list_t * match_list_init();
void match_list_process(match_list_t * list, bool (*funct_p) (match_data_t * fpa));
bool match_list_is_empty(match_list_t * list);
#endif