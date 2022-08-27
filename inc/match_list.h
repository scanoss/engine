/**
*@file match_list.h
*@date 08 Aug 2022
*@brief Main match/component "objects" definitions. As is know C languaje does not have "objects", but we are going to use
* this word since the code is organized like a 	class.
*#Introduction
* Version 5 of the engine is based in a deep refactoring, changing the match selection process and component filling, from
* statics structures to dynamic linked list. In this new organization three objects are cleary defined:
* -SCAN: is defined by "scan_data_t" and contains the properties and methods related the file being scanned.
* -MATCH: is definned by "match_data_t" and contains properties and methods related with the match "matching" with the scanned file.
* -COMPONENT: is definned by "match_data_t" and contains properties and methods related with the open source component of a match.
*
* When the engine process a scan, this is search matches for a wfp, the result can be one, many, or none matches depending the case.
* So, the first step is define the type of scan and in consequence of its match (match_t).
*-Full file match: the md5 of the file was found in the KB. There is only one possible match.
*-Snippet match: the md5 was not found in the KB. May be multiples file matching against differents snippets in the scanned file.
*-None: the snippet scan finish without results.
*
*One determined the possible matches, the engine has to determinate the right open source component for each one. It is very common
*have more than one valid posibility. In that case the engine will select as best component the oldest. Also it is possible request
*the engine for more than one component per match.
*
*#Nested linked list
*As was said in the previous introduction, a SCAN can have multiple matches and a MATCH can have multiple components.
*Moreover, the number of matches or components will change depending what we are scanning. So, linked list will supply
*the needed flexibility and also is a efficient method to keep the information sorted.
*
 * +------------+
 * |   SCAN     |
 * |            |
 * | file md5   |
 * | file path  |
 * | wfp data   |
 * | match type |
 * | matches LL +-----------+
 * | etc...     |           |
 * +------------+           |
 *                          v
 *                    MATCH ITEM           COMPONENT ITEM         COMPONENT ITEM
 *                   +---------------+    +-----------------+    +-----------------+
 *                   |  MATCH        |    |  COMPONENT      |    |  COMPONENT      |
 *                   |               |    |                 |    |                 |
 *                   | file md5      |    | purl            |    | purl            |
 *                   | line ranges   |    | version         |    | version         |
 *                   | source ranges |    | url             |    | url             |
 *                   | components LL +--->| licenses        +--->| licenses        +----> ...
 *                   |               |    | vulnerabilities |    | vulnerabilities |
 *                   | etc...        |    | etc...          |    | etc...          |
 *                   +-----+---------+    +-----------------+    +-----------------+
 *                         |
 *                         v
 *                    MATCH ITEM           COMPONENT ITEM         COMPONENT ITEM
 *                   +---------------+    +-----------------+    +-----------------+
 *                   |  MATCH        |    |  COMPONENT      |    |  COMPONENT      |
 *                   |               |    |                 |    |                 |
 *                   | file md5      |    | purl            |    | purl            |
 *                   | line ranges   |    | version         |    | version         |
 *                   | source ranges |    | url             |    | url             |
 *                   | components LL +--->| licenses        +--->| licenses        +-----> ---
 *                   |               |    | vulnerabilities |    | vulnerabilities |
 *                   | etc...        |    | etc...          |    | etc...          |
 *                   +-----+---------+    +-----------------+    +-----------------+
 *                         |
 *                         |
 *                         v
 *                         ---
 *
* @see https://github.com/scanoss/engine/blob/master/inc/match_list.h
**/
#ifndef __MATCH_LIST_H
#define __MATCH_LIST_H
#include <stdint.h>
#include <sys/queue.h>
#include <stdbool.h>

#define MD5_LEN 16
#define MAX_PURLS 10
#define MAX_FIELD_LN 1024

#define SCAN_MAX_SNIPPETS_DEFAULT 1
#define SCAN_MAX_COMPONENTS_DEFAULT 3


typedef enum {MATCH_NONE, MATCH_FILE, MATCH_SNIPPET, MATCH_BINARY} match_t;
typedef struct match_data_t match_data_t; /* Forward declaration */
typedef struct scan_data_t scan_data_t; /* Forward declaration*/

/**
 * @brief Component object definition.
 * 
 */
typedef struct component_data_t
{
	char * vendor; /* component vendor */
	char * component; /* component name */
	char * version; /* component version */
	char * release_date; /* component release date */
	char * latest_release_date; /* lastest relese date for this component */
	char * latest_version; /* lastest version for this component */
	char * license; /* component declared license */
	char * url; /* component url */
	char * file; /* component file path */	
	char * main_url; /* main file url in the component */
	bool url_match; /* type of url match*/
	/* PURL array */
	char *purls[MAX_PURLS]; /* PURLs array */
	uint8_t *purls_md5[MAX_PURLS]; /*PURLs md5*/
	int vulnerabilities; /*component vulnerabilities number */
	bool identified; /* was this component indentified in a provided SBOM */
	int path_ln; /* component path lenght: number of subdirectories in the path*/
	uint8_t url_md5[MD5_LEN]; /*url md5*/
	int age; /*component age */
	uint32_t * crclist; /* pointer to crc list used in part of the process */
	uint8_t * file_md5_ref; /*pointer to the md5 of the matched file */
	char * copyright_text; /* used in json output generation */
	char *license_text; /* used in json output generation */
	char * vulnerabilities_text; /* used in json output generation */
	char * dependency_text; /* used in json output generation */
} component_data_t;

/**
 * @brief Define a list of component_data_t
 * 
 */
LIST_HEAD(comp_listhead, comp_entry) comp_head;
struct comp_listhead *cheadp;                 /* List head. */
struct comp_entry {
    LIST_ENTRY(comp_entry) entries;          /* List. */
    component_data_t * component;
};

/**
 * @brief Define the object with the component list head and some useful properties.
 * 
 */
typedef struct component_list_t
{
	struct comp_listhead headp;
	int items;
	int max_items;
	bool autolimit;
	match_data_t * match_ref;
	struct comp_entry * last_element;
	struct comp_entry * last_element_aux;
} component_list_t;

/**
 * @brief  Match object definition.
 * 
 */
typedef struct match_data_t
{
	scan_data_t * scan_ower;
	component_list_t component_list; /*Component list object */ 
	match_t type; /*math type (none, snippet, file) */
    int hits; /*match hits number, more hits equal bigger snippet matching*/
	char * line_ranges; /*input snippet line ranges */
	char * oss_ranges; /* kb snippet line ranges */
	char * matched_percent; /* matched percent */
	int  path_ln; /*file path lenght*/ //TODO check if this is needed.
	uint8_t file_md5[MD5_LEN]; /* file md5 */
	char source_md5[MD5_LEN * 2 + 1]; /*matched file md5 in hex format */
    uint8_t * matchmap_reg; /* pointer to matchmap record */
	char * snippet_ids; /* comma separated list of matching snippet ids */
	uint32_t * crclist; /* pointer to crc list used in for processing */
	char * quality_text; /* quality string used in json output format */
	char * crytography_text; /* crytography string used in json output format */
	uint16_t from;
} match_data_t;

/**
 * @brief Matches list definition
 * 
 */
LIST_HEAD(listhead, entry) head;
struct listhead *headp;                 /* List head. */
struct entry {
    LIST_ENTRY(entry) entries;          /* List. */
    match_data_t * match;
};
/**
 * @brief Matches list object definition. Contains the matches list head and some useful properties.
 * 
 */
typedef struct match_list_t
{
	struct listhead headp; /*pointer to list head */
	int items; /*number of items in the list */
	int max_items; /*list max items*/
	bool autolimit; /*list autolimited */
	scan_data_t * scan_ref; /*pointer to scan owning the matches list */
	struct entry * last_element;  /*list last element */
	struct entry * last_element_aux; /* element previous to list last element */
	match_data_t * best_match; /*pointer to best match of the list */
} match_list_t;

#define MAX_SNIPPET_IDS_RETURNED 10000
#define WFP_LN 4
#define WFP_REC_LN 18
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

#define MAX_MULTIPLE_COMPONENTS 10
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

/* Public functions declaration */

scan_data_t * scan_data_init(char *target, int max_snippets, int max_components);

void match_list_print(match_list_t * list, bool (*printer) (match_data_t * fpa), char * separator);
void match_list_debug(match_list_t * list);
bool match_list_add(match_list_t * list, match_data_t * new_match, bool (* val) (match_data_t * a, match_data_t * b), bool remove_a);
void match_list_destroy(match_list_t * list);
match_data_t * match_data_copy(match_data_t * in);
match_list_t * match_list_init(bool autolimit, int max_items, scan_data_t * scan_ref);
void match_list_process(match_list_t * list, bool (*funct_p) (match_data_t * fpa, void * fpb));
bool match_list_is_empty(match_list_t * list);
void match_data_free(match_data_t *data);
void component_list_init(component_list_t *comp_list, int max_items);
bool component_list_add(component_list_t * list, component_data_t * new_comp, bool (* val) (component_data_t * a, component_data_t * b), bool remove_a);
void component_data_free(component_data_t * data);
void component_list_print(component_list_t * list, bool (*printer) (component_data_t * fpa), char * separator);
bool component_date_comparation(component_data_t * a, component_data_t * b);
component_data_t * component_data_copy(component_data_t * in);
#endif