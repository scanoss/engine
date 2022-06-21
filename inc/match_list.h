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

void match_list_print(struct listhead * list, bool (*printer) (match_data_t * fpa), char * separator);
void match_list_debug(struct listhead * list);
bool match_list_add(struct listhead * list, match_data_t * new_match, bool (* val) (match_data_t * a, match_data_t * b), bool remove_a);
void match_list_destroy(struct listhead * list);
struct listhead * match_list_init();
void match_list_process(struct listhead * list, bool (*funct_p) (match_data_t * fpa));
bool match_list_is_empty(struct listhead * list);
#endif