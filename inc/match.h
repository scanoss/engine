#ifndef __MATCH_H
    #define __MATCH_H

#include "scanoss.h"
#include "scan.h"
/**
 * @brief  Match object definition.
 * 
 */
typedef struct match_data_t
{
	scan_data_t * scan_ower; /*pointer to scan owning the match */
	component_list_t component_list; /*Component list object */ 
	match_t type; /*math type (none, snippet, file) */
    int hits; /*match hits number, more hits equal bigger snippet matching*/
	int lines_matched; /*number of matched lines*/
	char * line_ranges; /*input snippet line ranges */
	char * oss_ranges; /* kb snippet line ranges */
	int matched_percent; /* matched percent */
	int  path_ln; /*file path lenght*/ //TODO check if this is needed.
	uint8_t file_md5[MD5_LEN]; /* file md5 */
	char source_md5[MD5_LEN * 2 + 1]; /*matched file md5 in hex format */
    matchmap_entry * matchmap_reg; /* pointer to matchmap record */
	char * snippet_ids; /* comma separated list of matching snippet ids */
	uint32_t * crclist; /* pointer to crc list used in for processing */
	char * quality_text; /* quality string used in json output format */
	char * crytography_text; /* crytography string used in json output format */
	bool wfp1_evidence; /* the snippet candidate qualifies as a match with its wfp1 hits alone */
	int hits_wfp1; /* wfp1 hits, matched lines and percent (only when wfp1_evidence) */
	int lines_matched_wfp1;
	int matched_percent_wfp1;
} match_data_t;

/* Snippet candidates are ranked and selected by their wfp1 evidence when they qualify as a
   match with their wfp1 hits alone: wfp2 adds recall, but it tells close copies and versions
   apart worse than wfp1. Otherwise (files found by wfp2, file matches) the total is used. */
static inline int match_selection_hits(const match_data_t *m)
{
	return m->wfp1_evidence ? m->hits_wfp1 : m->hits;
}

static inline int match_selection_lines(const match_data_t *m)
{
	return m->wfp1_evidence ? m->lines_matched_wfp1 : m->lines_matched;
}

static inline int match_selection_percent(const match_data_t *m)
{
	return m->wfp1_evidence ? m->matched_percent_wfp1 : m->matched_percent;
}

match_data_t * match_data_copy(match_data_t * in);
void match_data_free(match_data_t *data);

void output_matches_json(scan_data_t *scan);
void compile_matches(scan_data_t *scan);
match_list_t * match_select_m_best(scan_data_t * scan);
match_list_t * match_select_m_component_best(scan_data_t * scan);
bool component_from_file(struct ldb_table *table, uint8_t *key, uint8_t *subkey, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr);

#endif
