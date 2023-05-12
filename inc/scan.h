#ifndef __SCAN_H
    #define __SCAN_H

#include "scanoss.h"
#include "match_list.h"
#define MAX_MULTIPLE_COMPONENTS 10
#define MAX_SNIPPET_IDS_RETURNED 10000
#define MATCHMAP_RANGES 10
/**
 * @brief Structure used to define the snippet ranges.
 * 
 */
typedef struct matchmap_range
{
	uint16_t from;
	uint16_t to;
	uint16_t oss_line;
} matchmap_range;

/**
 * @brief Structured used to define a matchmap entry used the snippet processing logic.
 * 
 */

typedef struct matchmap_entry
{
	uint8_t md5[MD5_LEN];
	uint16_t hits;
	matchmap_range range[MATCHMAP_RANGES];
	uint8_t lastwfp[WFP_LN];
} matchmap_entry;

/**
 * @brief Scan object definition.
 * "matches_list_array" is an array of "match_list_t" an it is used for the snippet selection algorithm join to "matches_list_array_indirection"
 * to indentify different component during the snippet scanning.
 * 
 */
typedef struct scan_data_t
{
	uint8_t md5[MD5_LEN]; /* file md5 */
	char *file_path; /* file path */
	char *file_size; /* file size */ //TODO remove if it is unused.
	char source_md5[MD5_LEN * 2 + 1];  /* source file md5 in hex format */
	uint32_t *hashes; /* pointer to wfp hashes*/
	uint32_t *lines; /*pointer to line hashes */
	uint32_t hash_count; /* count of wfp hashes */
	long timer; /*timer for execution profile*/
	bool preload; /*used in hash scanning */
	int total_lines; /* total file lines */
	match_t match_type; /* match_t (file, snippet, none), this is replicated in each match in the matches list */
	matchmap_entry *matchmap; /*matchmap pointer, used in snippet scanning */
	uint32_t matchmap_size; /*size of the match map */
	uint8_t *match_ptr; // pointer to matching record in match_map
	match_list_t * matches_list_array[MAX_MULTIPLE_COMPONENTS]; /* array of "match_list_t", each snippet with different "from line" will generate its own matches list */
	int matches_list_array_index; /* elements in the matches list array*/
	int  matches_list_array_indirection[MAX_MULTIPLE_COMPONENTS]; /*used to identify different snippets components, this mantain a reference to the snippet "from line" */
	match_data_t * best_match; /* Pointer to the best match in the scan, will be selected applying the best match selection logic */
	int max_snippets_to_process; /* Limit to each match list, by default is list is "autolimited"*/
	int max_components_to_process; /* Max component to retrieve during snippet scanning */
	int max_snippets_to_show; //TODO
	int max_components_to_show; //TODO
} scan_data_t;

extern bool force_snippet_scan;

scan_data_t * scan_data_init(char *target, int max_snippets, int max_components);
void scan_data_free (scan_data_t * scan);

void ldb_scan(scan_data_t * scan);
match_t ldb_scan_snippets(scan_data_t *scan_ptr);
int wfp_scan(char * path, int scan_max_snippets, int scan_max_components);
int hash_scan(char *path, int scan_max_snippets, int scan_max_components);

#endif
