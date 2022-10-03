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

match_data_t * match_data_copy(match_data_t * in);
void match_data_free(match_data_t *data);

void output_matches_json(scan_data_t *scan, char * report);
void compile_matches(scan_data_t *scan);
match_list_t * match_select_m_best(scan_data_t * scan);
match_list_t * match_select_m_component_best(scan_data_t * scan);
#endif
