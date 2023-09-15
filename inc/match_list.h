/**
*@file match_list.h
*@date 08 Aug 2022
*@brief Main match/component "objects" definitions. As is know C language does not have "objects", but we are going to use
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
#include "scanoss.h"
#include "component.h"

#define SCAN_MAX_SNIPPETS_DEFAULT 	1
#define SCAN_MAX_COMPONENTS_DEFAULT 3

#define MATCH_LIST_TOLERANCE 0.9
typedef struct match_data_t match_data_t; /* Forward declaration */
typedef struct scan_data_t scan_data_t; /* Forward declaration*/

/**
 * @brief Define a list of component_data_t
 * 
 */
LIST_HEAD(comp_listhead, comp_entry);
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
 * @brief Matches list definition
 * 
 */
LIST_HEAD(listhead, entry);
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
	struct entry * last_element;  /*list last element */
	struct entry * last_element_aux; /* element previous to list last element */
	match_data_t * best_match; /*pointer to best match of the list */
} match_list_t;


/* Public functions declaration */

bool match_list_print(match_list_t * list, bool (*printer) (match_data_t * fpa), char * separator);
void match_list_debug(match_list_t * list);
bool match_list_add(match_list_t * list, match_data_t * new_match, bool (* val) (match_data_t * a, match_data_t * b), bool remove_a);
void match_list_destroy(match_list_t * list);
match_list_t * match_list_init(bool autolimit, int max_items);
void match_list_process(match_list_t * list, bool (*funct_p) (match_data_t * fpa));
bool match_list_is_empty(match_list_t * list);
void component_list_init(component_list_t *comp_list, int max_items);
bool component_list_add(component_list_t * list, component_data_t * new_comp, bool (* val) (component_data_t * a, component_data_t * b), bool remove_a);
void component_list_print(component_list_t * list, bool (*printer) (component_data_t * fpa), char * separator);
void component_list_destroy(component_list_t *list);
bool component_list_add_binary(component_list_t *list, component_data_t *new_comp, bool (*val)(component_data_t *a, component_data_t *b), bool remove_a);

#endif
