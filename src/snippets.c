// SPDX-License-Identifier: GPL-2.0-or-later
/*
* src/snippets.c
*
* Snippet scanning subroutines
*
* Copyright (C) 2018-2021 SCANOSS.COM
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.

* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/**
  @file snippets.c
  @date 30 Dec 2020
  @brief Contains the functions used for  snippets processing
 
  Long description // TODO
  @see https://github.com/scanoss/engine/blob/master/src/scan.c
 */

#include "ignorelist.h"
#include "util.h"
#include "debug.h"
#include "limits.h"
#include "scanoss.h"
#include "ldb.h"
#include "decrypt.h"
#include "file.h"
#include "match.h"
#include "match_list.h"

int map_rec_len;
int matchmap_max_files = MAX_FILES;

/**
 * @brief Set map hits to zero for the given match
 * @param match pointer to match
 */
void clear_hits(uint8_t *match)
{
	if (!match) return;
	match[MD5_LEN] = 0;
	match[MD5_LEN + 1] = 0;
}

/**
 * @brief Returns the number of entries for a md5 into the files table.
 * @param md5 MD5 pointer
 * @return lenght of shortest path
 */
int get_match_popularity(uint8_t *md5)
{
	/* Direct component match has a top priority */
	if (!ldb_key_exists(oss_file, md5)) 
		return 0;

	int set = 0;
	ldb_fetch_recordset(NULL, oss_file, md5, false, count_all_files, (void *) &set);

	return set;
}

/**
 * @brief If the extension of the matched file does not match the extension of the scanned file
 *	and the matched file is not among known source code extensions, the match will be discarded
 * 
 * @param scan scan data pointer
 * @param md5 match md5
 * @return true 
 * @return false 
 */
bool snippet_extension_discard(scan_data_t *scan, uint8_t *md5)
{
	bool discard = false;

	char *ext1 = extension(scan->file_path);
	char *ext2 = get_file_extension(md5);

	if (!ext1) return false;
	if (!ext2) return false;

	if (!*ext1) return false;
	if (!*ext2) return false;

	if (strcmp(ext1, ext2))
		if (!known_src_extension(ext2)) discard = true;

	if (discard) scanlog("Discarding matched extension %s for %s\n", ext2, scan->file_path);

	free(ext2);
	return discard;
}

/**
 * @brief Compare to matches by hits
 * 
 * @param a first match to compare to. 
 * @param b second match to compare.
 * @return true 
 * @return false 
 */
static bool hit_test(match_data_t * a, match_data_t * b)
{
	if (a->hits <= b->hits)
		return true;
	else
		return false;
}
/**
 * @brief Fill the matches list array based on the matchmap. The possible matches will be sorted by hits number.
 * 
 * @param scan 
 */
void biggest_snippet(scan_data_t *scan)
{
	scanlog("biggest_snippet\n");
	/*Initialize the auxiliary indirection list */
	for (int i=0; i< scan->max_snippets_to_process; i++)
		scan-> matches_list_array_indirection[i] = -1;

	int snippet_tolerance = range_tolerance / scan->max_snippets_to_process + min_match_lines; /* Used to define bounds between two possible snippets */
	/*Fill the matches list with the files from the matchmap */
	for (int j = 0; j < scan->matchmap_size; j++)
	{
		if (scan->matchmap[j].hits >= min_match_hits) /* Only consider file with more than min_match_hits */
		{
			match_data_t * match_new = calloc(1,sizeof(match_data_t)); /* Create a match object */
			memcpy(match_new->file_md5, scan->matchmap[j].md5, MD5_LEN);
			match_new->hits = scan->matchmap[j].hits;
			match_new->matchmap_reg = scan->matchmap[j].md5;
			match_new->type = scan->match_type;
			match_new->from = scan->matchmap[j].range->from;
			strcpy(match_new->source_md5, scan->source_md5);
			match_new->scan_ower = scan;
			bool found = false;
			int i = 0;
			for (; i< scan->matches_list_array_index; i++) /*Check if there is already a list for this line ranges */
			{
				if (scan-> matches_list_array_indirection[i] >-1 && 
					abs(scan-> matches_list_array_indirection[i] - match_new->from) < snippet_tolerance)
					{	
						found = true;
						break;
					}
			}

			if (!found) /*If there is no list for the snippet range we have to create a new one */
			{
				if (scan->matches_list_array_index < scan->max_snippets_to_process) /* Check for the list limit */
				{
					scan-> matches_list_array_indirection[scan->matches_list_array_index] = match_new->from; /*update indirection*/
					scan->matches_list_array[scan->matches_list_array_index] = match_list_init(true, 1); /*create the list*/
					i = scan->matches_list_array_index; /* update index*/
					scan->matches_list_array_index++; 
				}
				else
					i = scan->max_snippets_to_process - 1; /*add in the last available list if there is no more space for new lists*/
			}
							

			if (!match_list_add(scan->matches_list_array[i], match_new, hit_test, true)) /*Add the match in the selected list */
			{
				scanlog("Rejected match with %d hits\n", match_new->hits);
				match_data_free(match_new);	/* the the memory if the match was not accepted in the list */
			}
		}
	}
	for (int i = 0; i < scan->matches_list_array_index; i++)
	{
		scanlog("Match list N %d, with %d matches. %d <= HITS <= %d \n", i, scan->matches_list_array[i]->items,
																		scan->matches_list_array[i]->last_element->match->hits,
																		scan->matches_list_array[i]->headp.lh_first->match->hits);
		struct entry *item = NULL;
		LIST_FOREACH(item, &scan->matches_list_array[i]->headp, entries)
		{
			char md5_hex[MD5_LEN * 2 +1];
			ldb_bin_to_hex(item->match->file_md5, MD5_LEN, md5_hex);
			scanlog("%s\n", md5_hex);
		}
	}
}

/**
 * @brief Handler function to collect all file ids.
 * Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr //TODO
 * @return //TODO
 */
static bool get_all_file_ids(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	uint8_t *record = (uint8_t *) ptr;
	if (datalen)
	{
		uint32_t size = uint32_read(record);

		/* End recordset fetch if MAX_QUERY_RESPONSE is reached */
		if (size + datalen + 4 >= MAX_QUERY_RESPONSE) return true;

		/* End recordset fetch if MAX_FILES are reached for the snippet */
		if ((WFP_REC_LN * matchmap_max_files) <= (size + datalen)) return true;

		/* Save data and update dataln */
		memcpy(record + size + 4, data, datalen);
		uint32_write(record, size + datalen);
	}
	return false;
}

/**
 * @brief Skip unwanted snippets
 * @param src snippet
 * @param srcln snippet len
 * @return true if the snippet was ignored
 */
bool skip_snippets(char *src, uint64_t srcln)
{
	if (srcln > SKIP_SNIPPETS_IF_FILE_BIGGER)
	{
		scanlog("Skipping snippets: File over size limit\n");
		return true;
	}
	if (srcln != strlen(src))
	{
		scanlog("Skipping snippets: Binary file\n");
		return true; // is binary
	}
	if (unwanted_header(src))
	{
		scanlog("Skipping snippets: Ignored contents\n");
		return true;
	}
	return false;
}

/**
 * @brief Add snippets id to a scan
 * @param scan scan data pointer
 * @param from snippet start
 * @param to snippet end
 */
void add_snippet_ids(match_data_t *match, char * snippet_ids, long from, long to)
{
	int maxlen = MAX_SNIPPET_IDS_RETURNED * WFP_LN * 2 + MATCHMAP_RANGES;
	bool found = false;
	/* Walk scan->lines array */
	for (int i = 0; i < match->scan_ower->hash_count; i++)
	{
		if (match->scan_ower->lines[i] > to - 1) break;

		/* If line is within from and to, add snippet id to list */
		if (match->scan_ower->lines[i] >= from - 1)
		{
			found = true;

			char hex[9] = "\0";
			hex[8] = 0;
			uint32_t hash = match->scan_ower->hashes[i];
			uint32_reverse((uint8_t *)&hash);
			ldb_bin_to_hex((uint8_t *)&hash, WFP_LN, hex);

			if (strlen(snippet_ids) + WFP_LN * 2 + 1 >= maxlen) break;
			sprintf(snippet_ids + strlen(snippet_ids), "%s", hex);
		}
	}

	if (found) strcat(snippet_ids, ",");
	scanlog("SNIPPETS ID: %s\n", snippet_ids);
}

/**
 * @brief Assemble line ranges from ranges into scan->line_ranges and oss_ranges
 * @param ranges input ranges list
 * @param scan[out] pointer to scan data
 * @return hits
 */
int ranges_assemble(matchmap_range *ranges, char * line_ranges, char * oss_ranges)
{
	int out = 0;

	/* Walk ranges */
	for (int i = MATCHMAP_RANGES - 1; i >= 0; i--)
	{
		int to = ranges[i].to;
		int from = ranges[i].from;
		int oss = ranges[i].oss_line;
		if (from && to && oss)
		{
			/* Add commas unless it is the first range */
			if (*line_ranges) strcat(line_ranges, ",");
			if (*oss_ranges) strcat(oss_ranges, ",");

			/* Add from-to values */
			sprintf (line_ranges + strlen(line_ranges), "%d-%d", from, to);
			sprintf (oss_ranges + strlen(oss_ranges), "%d-%d", oss, to - from + oss);

			/* Increment hits */
			out += (to - from);
		}
	}
	return out;
}

/**
 * @brief Join overlapping ranges 
 * @param ranges ranges list to process
 */
void ranges_join_overlapping(matchmap_range *ranges)
{
	/* Walk ranges MATCHMAP_RANGES times */
	for (int a = 0; a < MATCHMAP_RANGES; a++)
	for (int i = 0; i < MATCHMAP_RANGES - 1; i++)
	{
		/* Join range */
		if (ranges[i].from && ranges[i + 1].to >= ranges[i].from)
		{
			ranges[i].from = ranges[i + 1].from;
			ranges[i + 1].from = 0;
			ranges[i + 1].to = 0;
		}
	}
}

/**
 * @brief Remove empty ranges, shifting remaining ranges 
 * 
 * @param ranges ranges list to process
 */
void ranges_remove_empty(matchmap_range *ranges)
{
	/* Walk ranges MATCHMAP_RANGES times */
	for (int a = 0; a < MATCHMAP_RANGES; a++)
	for (int i = 0; i < MATCHMAP_RANGES - 1; i++)
	{
		if (!ranges[i].from && ranges[i+1].from)
		{
			ranges[i].from = ranges[i + 1].from;
			ranges[i + 1].from = 0;
			ranges[i].to = ranges[i + 1].to;
			ranges[i + 1].to = 0;
			ranges[i].oss_line = ranges[i + 1].oss_line;
			ranges[i + 1].oss_line = 0;
		}
	}
}

/**
 * @brief Add SNIPPET_LINE_TOLERANCE to ranges
 * 
 * @param ranges ranges list to process
 * @param scan scan data pointer
 */
void ranges_add_tolerance(matchmap_range *ranges, scan_data_t *scan)
{
	/* Walk ranges */
	for (int i = 0; i < MATCHMAP_RANGES; i++)
	{
		int to = ranges[i].to;
		int from = ranges[i].from;
		int oss = ranges[i].oss_line;
		if (from && to && oss)
		{
			from -= SNIPPET_LINE_TOLERANCE;
			oss -= SNIPPET_LINE_TOLERANCE;
			to += SNIPPET_LINE_TOLERANCE;

			/* Check bounds */
			if (from < 1) from = 1;
			if (oss < 1) oss = 1;
			if (to > scan->total_lines) to = scan->total_lines;

			ranges[i].to = to;
			ranges[i].from = from;
			ranges[i].oss_line = oss;
		}
	}
}

/**
 * @brief Compiles list of line ranges, returning total number of hits (lines matched)
 * 
 * @param scan point to scan data to process
 * @return uint32_t snippet hits
 */
uint32_t compile_ranges(match_data_t *match) {

	char line_ranges[MAX_FIELD_LN * 2] = "\0";
	char oss_ranges[MAX_FIELD_LN * 2] = "\0";
	char snippet_ids[MAX_SNIPPET_IDS_RETURNED * WFP_LN * 2 + MATCHMAP_RANGES + 1] = "\0"; 
	if (!match->matchmap_reg)
	{
		scanlog("compile ranges fail");
		return 0;
	}

	uint16_t reported_hits = uint16_read(match->matchmap_reg + MD5_LEN);
	if (reported_hits < 2) return 0;

	/* Lowest tolerance simply requires selecting the higher match count */
	if (min_match_lines == 1)
	{
		asprintf(&match->line_ranges, "N/A");
		asprintf(&match->oss_ranges, "N/A");
		return uint16_read(match->matchmap_reg + MD5_LEN);
	}

	/* Revise hits and decrease if needed */
	for (uint32_t i = 0; i < MATCHMAP_RANGES; i++)
	{
		long from     = uint16_read(match->matchmap_reg + MD5_LEN + 2 + i * 6);
		long to       = uint16_read(match->matchmap_reg + MD5_LEN + 2 + i * 6 + 2);
		long delta = to - from;

		if (to < 1) break;

		/* Ranges to be ignored (under min_match_lines) should decrease hits counter */
		if ((delta) < min_match_lines)
		{
			/* Single-line range decreases by 1, otherwise decrease by 2 (from and to) */
			reported_hits -= ((delta == 0) ? 1 : 2);
		}

		/* Exit if hits is below two */
		if (reported_hits < 2)
		{
			scanlog("Discarded ranges brings hits count to %u\n", reported_hits);
			return 0;
		}
	}

	int hits = 0;
	matchmap_range *ranges = calloc(sizeof(matchmap_range), MATCHMAP_RANGES);

	/* Count matched lines */
	for (uint32_t i = 0; i < MATCHMAP_RANGES; i++)
	{

		long from     = uint16_read(match->matchmap_reg + MD5_LEN + 2 + i * 6);
		long to       = uint16_read(match->matchmap_reg + MD5_LEN + 2 + i * 6 + 2);
		long oss_from = uint16_read(match->matchmap_reg + MD5_LEN + 2 + i * 6 + 4);

		scanlog("compile_ranges #%d = %ld to %ld\n", i, from, to);

		/* Determine if this is the last (first) range */
		bool first_range = false;
		if (i == MATCHMAP_RANGES) first_range = true;
		else if (!uint16_read(match->scan_ower->match_ptr + MD5_LEN + 2 + (i + 1) * 6 + 2)) first_range = true;

		if (to < 1) break;

		/* Add range as long as the minimum number of match lines is reached */
		if ((to - from) >= min_match_lines)
		{
			if (engine_flags & ENABLE_SNIPPET_IDS)
				add_snippet_ids(match, snippet_ids, from, to); //has to be reformulated

			/* Add tolerance to end of last range */
			if (!i)
			{
				to += range_tolerance;
				if (to > match->scan_ower->total_lines) to =  match->scan_ower->total_lines;
			}

			/* Add tolerance to start of first range */
			if (first_range)
			{
				from -= range_tolerance;
				if (from < 1) from = 1;
			}

			ranges[i].from = from;
			ranges[i].to= to;
			ranges[i].oss_line = oss_from;
		}
	}

	/* Add tolerances and assemble line ranges */
	ranges_add_tolerance(ranges, match->scan_ower);
	ranges_remove_empty(ranges);
	ranges_join_overlapping(ranges);
	hits = ranges_assemble(ranges, line_ranges, oss_ranges);
	match->line_ranges = strdup(line_ranges);
	match->oss_ranges = strdup(oss_ranges);
	match->snippet_ids = strdup(snippet_ids);
	free(ranges);
	return hits;
}

/**
 * @brief Ajust snippet match tolerance
 * @param scan pointer to scan data struct
 */
static void adjust_tolerance(scan_data_t *scan)
{
	bool skip = false;
	uint32_t wfpcount = scan->hash_count;

	if (!wfpcount) skip = true;
	else if (scan->lines[wfpcount-1] < 10) skip = true;

	if (skip) min_match_lines = 1;
	else
	{
		/* Range tolerance is the maximum amount of non-matched lines accepted
			 within a matched range. This goes from 21 in small files to 9 in large files */

		range_tolerance = 21 - floor(wfpcount / 21);
		if (range_tolerance < 9) range_tolerance = 9;

		/* Min matched lines is the number of matched lines in total under which the result
			 is ignored. This goes from 3 in small files to 10 in large files */

		min_match_lines = 3 + floor(wfpcount / 5);
		if (min_match_lines > 10) min_match_lines = 10;
	}

	scanlog("Tolerance: range=%d, lines=%d, wfpcount=%u\n", range_tolerance, min_match_lines, wfpcount);
}

/**
 * @brief Get inverted wfp from int32
 * @param wfpint32 int32 wfp
 * @param out[out] array with the bytes of the inverted wfp
 */
void wfp_invert(uint32_t wfpint32, uint8_t *out)
{
	uint8_t *ptr = (uint8_t*)&wfpint32;
	out[0]=ptr[3];
	out[1]=ptr[2];
	out[2]=ptr[1];
	out[3]=ptr[0];
}

/**
 * @brief Add line hit to all files
 * @param scan pointer to scan data
 * @param line line number
 * @param min_tolerance min tolerance
 */
void add_popular_snippet_to_matchmap(scan_data_t *scan, uint32_t line, uint32_t min_tolerance)
{
	/* Travel the match map */
	for (long n = 0; n < scan->matchmap_size; n++)
	{
		/* Search for the range to expand */
		for (int t = 0; t < MATCHMAP_RANGES; t++)
		{
			/* Exit if no more ranges are recorded for this file */
			if (!scan->matchmap[n].range[t].from) continue;

			int gap = scan->matchmap[n].range[t].from - line;

			/* Increase existing range */
			if (gap < range_tolerance || gap <= min_tolerance)
			{
				scan->matchmap[n].range[t].from = line;
				continue;
			}
		}
	}
}

/**
 * @brief Add matchmap to scan structure
 * @param scan pointer to scan dats structure
 * @param md5s md5 list
 * @param md5s_ln md5 list lenght
 * @param wfp pointer t wfp
 * @param line line number
 * @param min_tolerance min tolerance
 */
void add_files_to_matchmap(scan_data_t *scan, uint8_t *md5s, uint32_t md5s_ln, uint8_t *wfp, uint32_t line, uint32_t min_tolerance)
{
	uint32_t from = 0;
	uint32_t to = 0;
	long map_rec_len = sizeof(matchmap_entry);

	/* Recurse each record from the wfp table */
	for (int n = 0; n < md5s_ln; n += WFP_REC_LN)
	{
		/* Retrieve an MD5 from the recordset */
		memcpy(scan->md5, md5s + n, MD5_LEN);

		/* The md5 is followed by the line number where the wfp hash was seen */
		uint16_t oss_line = uint16_read(md5s + n + MD5_LEN);

		/* Check if md5 already exists in map */
		long found = -1;
		for (long t = 0; t < scan->matchmap_size; t++)
		{
			if (md5cmp(scan->matchmap[t].md5, scan->md5))
			{
				found = t;
				break;
			}
		}

		if (found < 0)
		{
			/* Not found. Add MD5 to map */
			if (scan->matchmap_size >= matchmap_max_files) continue;

			found = scan->matchmap_size;

			/* Clear row */
			memset(scan->matchmap[found].md5, 0, map_rec_len);

			/* Write MD5 */
			memcpy(scan->matchmap[found].md5, scan->md5, MD5_LEN);
		}

		/* Search for the right range */
		uint8_t *lastwfp = scan->matchmap[found].lastwfp;

		/* Skip if we are hitting the same wfp again for this file) */
		if (!memcmp(wfp, lastwfp, 4)) continue;

		for (uint32_t t = 0; t < MATCHMAP_RANGES; t++)
		{
			from = scan->matchmap[found].range[t].from;
			to   = scan->matchmap[found].range[t].to;
			int gap = from - line;

			/* New range */
			if (!from && !to)
			{
				/* Update from and to */
				scan->matchmap[found].range[t].from = line;
				scan->matchmap[found].range[t].to = line;
				scan->matchmap[found].range[t].oss_line = oss_line;
				scan->matchmap[found].hits++;
				break;
			}

			/* Another hit in the same line, no need to expand range */
			else if (from == line)
			{
				scan->matchmap[found].hits++;
				break;
			}

			/* Increase range */
			else if (gap < range_tolerance || gap <= min_tolerance)
			{
				/* Update range start (from) */
				scan->matchmap[found].range[t].from = line;
				scan->matchmap[found].hits++;
				scan->matchmap[found].range[t].oss_line = oss_line;
				break;
			}
		}

		/* Update last wfp */
		memcpy(lastwfp, wfp, 4);

		if (found == scan->matchmap_size) scan->matchmap_size++;
	}
}

/**
 * @brief Query all wfp and add resulting file ids to the matchmap
		Scan is done from last to first line, because headers and
		first lines are statistically more common than the end of
		the file
 * @param scan pointer to scan data to be processed
 * @return match type
 */
match_t ldb_scan_snippets(scan_data_t *scan) {

	scanlog("ldb_scan_snippets\n");
	if (!scan->hash_count) 
	{
		scanlog("No hashes return NONE\n");
		return MATCH_NONE;
	}

	if (engine_flags & DISABLE_SNIPPET_MATCHING) return MATCH_NONE;

	if (trace_on) scanlog("Checking snippets. Traced (-qi) matches marked with *\n");
	else scanlog("Checking snippets\n");

	adjust_tolerance(scan);

	uint8_t *md5_set = malloc(MAX_QUERY_RESPONSE);
	uint8_t wfp[4];
	int consecutive = 0;
	uint32_t line = 0;
	uint32_t last_line = 0;
	bool traced = false;
	int jump_lines = 0;

	/* Limit snippets to be scanned  */
	uint32_t scan_from = 0;
	uint32_t scan_to = scan->hash_count - 1;
	if (scan->hash_count > MAX_SNIPPETS_SCANNED)
	{
		scan_from = scan->hash_count - MAX_SNIPPETS_SCANNED;
	}

	/* Compare each wfp, from last to first */
	for (long i = scan_to; i >= scan_from; i--)
	{
		/* Read line number and wfp */
		line = scan->lines[i];
		wfp_invert(scan->hashes[i], wfp);

		/* Get all file IDs for given wfp */
		uint32_write(md5_set, 0);
		ldb_fetch_recordset(NULL, oss_wfp, wfp, false, get_all_file_ids, (void *) md5_set);

		/* md5_set starts with a 32-bit item count, followed by all 16-byte records */
		uint32_t md5s_ln = uint32_read(md5_set);
		uint8_t *md5s = md5_set + 4;

		/* If popularity is exceeded, matches for this snippet are added to all files */
		if (md5s_ln > (WFP_POPULARITY_THRESHOLD * WFP_REC_LN))
		{
			scanlog("Snippet %02x%02x%02x%02x (line %d) >= WFP_POPULARITY_THRESHOLD\n", wfp[0], wfp[1], wfp[2], wfp[3], line);
		//	add_popular_snippet_to_matchmap(scan, line, last_line - line);
			continue;
		}

		if (trace_on)
		{
			traced = false;
			for (uint32_t j = 0; j < md5s_ln && !traced; j++)
				if (!memcmp(md5s + j, trace_id, MD5_LEN)) traced = true;
		}

		scanlog("Snippet %02x%02x%02x%02x (line %d) -> %u hits %s\n", wfp[0], wfp[1], wfp[2], wfp[3], line, md5s_ln / WFP_REC_LN, traced ? "*" : "");


		/* If a snippet brings more than "score" result by "hits" times in a row, we skip "jump" snippets */
		jump_lines = jump_lines / 2;
		if (scan->hash_count > consecutive_threshold)
		{
			if (md5s_ln > consecutive_score)
			{
				if (++consecutive >= consecutive_hits)
				{
					i -= consecutive_jump;
					consecutive = 0;
					if (i >= scan_from)
					{
						jump_lines = line - scan->lines[i];
						scanlog("Skipping %d snippets after %d consecutive_hits, raising tolerance by %d\n", consecutive_jump, consecutive_hits, jump_lines);
					}
				}
			}
		}

		/* Add snippet records to matchmap */
		if (jump_lines) scanlog("Tolerance increased by jump_lines = %d\n", jump_lines);
		add_files_to_matchmap(scan, md5s, md5s_ln, wfp, line, jump_lines + last_line - line);
		last_line = line;
	}

	free(md5_set);

	if (scan->matchmap_size) 
		return MATCH_SNIPPET;
	scanlog("Snippet scan has no matches\n");
	return MATCH_NONE;
}
