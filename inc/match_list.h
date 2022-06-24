#ifndef __MATCH_LIST_H
#define __MATCH_LIST_H
#include <stdint.h>
#include "scanoss.h"
#include <sys/queue.h>

#define MAX_PURLS 10

typedef enum {MATCH_NONE, MATCH_URL, MATCH_FILE, MATCH_SNIPPET} match_t;

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
	char * vulnerabilities_text;
	int path_ln;
	uint8_t url_md5[MD5_LEN];
	int age;
	bool url_match;
	uint32_t * crclist;
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
	component_list_t component_list;
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
	scan_data * scan_ref;  
} match_list_t;


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