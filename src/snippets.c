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
#include "stdlib.h"
int map_rec_len;
int matchmap_max_files = MAX_MATCHMAP_FILES;

/**
 * @brief If the extension of the matched file does not match the extension of the scanned file
 *	and the matched file is not among known source code extensions, the match will be discarded
 *
 * @param scan scan data pointer
 * @param md5 match md5
 * @return true
 * @return false
 */
bool snippet_extension_discard(match_data_t * match)
{
	bool discard = false;

	char *ext1 = extension(match->scan_ower->file_path);

	if (!ext1)
		return false;

	char *ext2 = get_file_extension(match->file_md5);
	
	if (!ext2)
		return false;

	if (*ext1 && *ext2 && strcmp(ext1, ext2))
		if (!known_src_extension(ext2))
			discard = true;

	if (discard)
		scanlog("Discarding matched extension %s for %s\n", ext2, ext1);

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
static bool hit_test(match_data_t *a, match_data_t *b)
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
	for (int i = 0; i < scan->max_snippets_to_process; i++)
		scan->matches_list_array_indirection[i] = -1;

	int snippet_tolerance = range_tolerance / scan->max_snippets_to_process + min_match_lines; /* Used to define bounds between two possible snippets */
	/*Fill the matches list with the files from the matchmap */
	for (int sector = 0; sector < 255; sector++)
	{
		int j = scan->matchmap_rank_by_sector[sector];
		
		if (j < 0)
			continue;
		
		if (scan->matchmap[j].hits >= min_match_hits) /* Only consider file with more than min_match_hits */
		{
			match_data_t *match_new = calloc(1, sizeof(match_data_t)); /* Create a match object */
			memcpy(match_new->file_md5, scan->matchmap[j].md5, MD5_LEN);
			match_new->hits = scan->matchmap[j].hits;
			match_new->matchmap_reg = scan->matchmap[j].md5;
			match_new->type = scan->match_type;
			match_new->from = scan->matchmap[j].range->from;
			strcpy(match_new->source_md5, scan->source_md5);
			match_new->scan_ower = scan;
			bool found = false;
			int i = 0;
			for (; i < scan->matches_list_array_index; i++) /*Check if there is already a list for this line ranges */
			{
				if (scan->matches_list_array_indirection[i] > -1 &&
					abs(scan->matches_list_array_indirection[i] - match_new->from) < snippet_tolerance)
				{
					found = true;
					break;
				}
			}

			if (!found) /*If there is no list for the snippet range we have to create a new one */
			{
				if (scan->matches_list_array_index < scan->max_snippets_to_process) /* Check for the list limit */
				{
					scan->matches_list_array_indirection[scan->matches_list_array_index] = match_new->from; /*update indirection*/
					scan->matches_list_array[scan->matches_list_array_index] = match_list_init(true, 1);	/*create the list*/
					i = scan->matches_list_array_index;														/* update index*/
					scan->matches_list_array_index++;
				}
				else
					i = scan->max_snippets_to_process - 1; /*add in the last available list if there is no more space for new lists*/
			}

			if (snippet_extension_discard(match_new) || !match_list_add(scan->matches_list_array[i], match_new, hit_test, true)) /*Add the match in the selected list */
			{
				scanlog("Rejected match with %d hits\n", match_new->hits);
				match_data_free(match_new); /* the the memory if the match was not accepted in the list */
			}
		}
	}
	/*just for loging*/
	if (debug_on)
	{
		for (int i = 0; i < scan->matches_list_array_index; i++)
		{
			scanlog("Match list N %d, with %d matches. %d <= HITS <= %d \n", i, scan->matches_list_array[i]->items,
					scan->matches_list_array[i]->last_element->match->hits,
					scan->matches_list_array[i]->headp.lh_first->match->hits);
			struct entry *item = NULL;
			LIST_FOREACH(item, &scan->matches_list_array[i]->headp, entries)
			{
				char md5_hex[MD5_LEN * 2 + 1];
				ldb_bin_to_hex(item->match->file_md5, MD5_LEN, md5_hex);
				scanlog("%s - %d\n", md5_hex, item->match->hits);
			}
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
#define MATCHMAP_ITEM_SIZE (matchmap_max_files)
static bool get_all_file_ids(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	uint8_t *record = (uint8_t *)ptr;

	if (datalen)
	{
		uint32_t size = uint32_read(record);
		/* End recordset fetch if MAX_QUERY_RESPONSE is reached */
		if (size + datalen + 4 >= WFP_REC_LN * MATCHMAP_ITEM_SIZE)
		{
			//memcpy(record + size + 4, data, WFP_REC_LN * MATCHMAP_ITEM_SIZE - size);
			//uint32_write(record, size + WFP_REC_LN * MATCHMAP_ITEM_SIZE);
			return true;
		}

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
void add_snippet_ids(match_data_t *match, char *snippet_ids, long from, long to)
{
	int maxlen = MAX_SNIPPET_IDS_RETURNED * WFP_LN * 2 + MATCHMAP_RANGES;
	bool found = false;
	/* Walk scan->lines array */
	for (int i = 0; i < match->scan_ower->hash_count; i++)
	{
		if (match->scan_ower->lines[i] > to - 1)
			break;

		/* If line is within from and to, add snippet id to list */
		if (match->scan_ower->lines[i] >= from - 1)
		{
			found = true;

			char hex[9] = "\0";
			hex[8] = 0;
			uint32_t hash = match->scan_ower->hashes[i];
			uint32_reverse((uint8_t *)&hash);
			ldb_bin_to_hex((uint8_t *)&hash, WFP_LN, hex);

			if (strlen(snippet_ids) + WFP_LN * 2 + 1 >= maxlen)
				break;
			sprintf(snippet_ids + strlen(snippet_ids), "%s", hex);
		}
	}

	if (found)
		strcat(snippet_ids, ",");
	scanlog("SNIPPETS ID: %s\n", snippet_ids);
}

/**
 * @brief Assemble line ranges from ranges into scan->line_ranges and oss_ranges
 * @param ranges input ranges list
 * @param scan[out] pointer to scan data
 * @return hits
 */
int ranges_assemble(matchmap_range *ranges, char *line_ranges, char *oss_ranges)
{
	int out = 0;
	/* Walk ranges */
	for (int i = 0; i < MATCHMAP_RANGES; i++)
	{
		int to = ranges[i].to;
		int from = ranges[i].from;
		int oss = ranges[i].oss_line;

		if (!from && !to)
			continue;
		else if (oss)
		{
			/* Add commas unless it is the first range */
			if (*line_ranges)
				strcat(line_ranges, ",");
			if (*oss_ranges)
				strcat(oss_ranges, ",");

			/* Add from-to values */
			sprintf(line_ranges + strlen(line_ranges), "%d-%d", from, to);
			sprintf(oss_ranges + strlen(oss_ranges), "%d-%d", oss, oss + (to - from));

			/* Increment hits */
			out += (to - from);
		}
	}
	return out;
}

int range_comp(const void *a, const void *b)
{
	matchmap_range *ra = (matchmap_range *)a;
	matchmap_range *rb = (matchmap_range *)b;
	if (rb->from == 0)
		return -1;
	if (ra->from == rb->from)
		return (ra->to - rb->to);
	return (ra->from - rb->from);
}
/**
 * @brief Join overlapping ranges
 * @param ranges ranges list to process
 */
void ranges_join_overlapping(matchmap_range *ranges)
{
	matchmap_range *out_ranges = calloc(sizeof(matchmap_range), MATCHMAP_RANGES);

	out_ranges[0] = ranges[0];
	int out_ranges_index = -1;
	
	for (int i = 0; i < MATCHMAP_RANGES; i++)
	{
		if (ranges[i].from && ranges[i].to)
		{
			if(out_ranges_index >= 0 && (ranges[i].from - range_tolerance <= out_ranges[out_ranges_index].to))
			{
				out_ranges[out_ranges_index].to = ranges[i].to;
				scanlog("join range %d with %d\n", i, out_ranges_index);
			}
			else
			{
				out_ranges_index++;
				out_ranges[out_ranges_index].from = ranges[i].from;
				out_ranges[out_ranges_index].to = ranges[i].to;
				out_ranges[out_ranges_index].oss_line = ranges[i].oss_line;	
			}
		}
	}

	memcpy(ranges, out_ranges, sizeof(matchmap_range) * MATCHMAP_RANGES);
	free(out_ranges);
}

/**
 * @brief Remove empty ranges, shifting remaining ranges
 *
 * @param ranges ranges list to process
 */
void ranges_sort(matchmap_range *ranges)
{
	qsort(ranges, MATCHMAP_RANGES, sizeof(matchmap_range), range_comp);
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
			from -= range_tolerance;
			oss -= range_tolerance;
			to += range_tolerance;

			/* Check bounds */
			if (from < 1)
				from = 1;

			if (oss < 1)
				oss = 1;

			if (to > scan->total_lines)
				to = scan->total_lines;

			ranges[i].to = to;
			ranges[i].from = from;
			ranges[i].oss_line = oss;
		}
		else if (!from && !to && !oss)
			break;
	}
}

/**
 * @brief Compiles list of line ranges, returning total number of hits (lines matched)
 *
 * @param scan point to scan data to process
 * @return uint32_t snippet hits
 */
uint32_t compile_ranges(match_data_t *match)
{

	char line_ranges[MAX_FIELD_LN * 2] = "\0";
	char oss_ranges[MAX_FIELD_LN * 2] = "\0";
	char snippet_ids[MAX_SNIPPET_IDS_RETURNED * WFP_LN * 2 + MATCHMAP_RANGES + 1] = "\0";
	if (!match->matchmap_reg)
	{
		scanlog("compile ranges fail");
		return 0;
	}

	uint16_t reported_hits = uint16_read(match->matchmap_reg + MD5_LEN);
	if (reported_hits < 2)
		return 0;

	/* Revise hits and decrease if needed */
	for (uint32_t i = 0; i < MATCHMAP_RANGES; i++)
	{
		long from = uint16_read(match->matchmap_reg + MD5_LEN + 2 + i * 6);
		long to = uint16_read(match->matchmap_reg + MD5_LEN + 2 + i * 6 + 2);
		long delta = to - from;

		if (to < 1)
			break;

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
	scanlog("min_match_lines: %d\n",min_match_lines);
	/* Count matched lines */
	int j = 0;
	for (uint32_t i = 0; i < MATCHMAP_RANGES; i++)
	{

		long from = uint16_read(match->matchmap_reg + MD5_LEN + 2 + i * 6);
		long to = uint16_read(match->matchmap_reg + MD5_LEN + 2 + i * 6 + 2);
		long oss_from = uint16_read(match->matchmap_reg + MD5_LEN + 2 + i * 6 + 4);

		scanlog("compile_ranges #%d = %ld to %ld - OSS from: %d\n", i, from, to, oss_from);

		if (to < 1)
			break;

		/* Add range as long as the minimum number of match lines is reached */
		if (abs(to - from) >= min_match_lines / 2)
		{
			if (engine_flags & ENABLE_SNIPPET_IDS)
				add_snippet_ids(match, snippet_ids, from, to); // has to be reformulated

			ranges[j].from = from;
			ranges[j].to = to;
			ranges[j].oss_line = oss_from;
			j++;
		}
	}
	
	/* Add tolerances and assemble line ranges */
	ranges_sort(ranges);

	scanlog("Accepted ranges:\n");

	for (uint32_t i = 0; i < MATCHMAP_RANGES; i++)
	{
		if ( ranges[i].from && ranges[i].to)
			scanlog("	%d = %ld to %ld - OSS from: %d\n", i, ranges[i].from, ranges[i].to, ranges[i].oss_line);
	}
	ranges_add_tolerance(ranges, match->scan_ower);
	ranges_join_overlapping(ranges);

	scanlog("Final ranges:\n");

	for (uint32_t i = 0; i < MATCHMAP_RANGES; i++)
	{
		if ( ranges[i].from && ranges[i].to)
			scanlog("	%d = %ld to %ld - OSS from: %d\n", i, ranges[i].from, ranges[i].to, ranges[i].oss_line);
	}

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

	if (!wfpcount)
		skip = true;
	else if (scan->lines[wfpcount - 1] < 10)
		skip = true;

	if (skip)
		min_match_lines = 1;
	else
	{
		/* Range tolerance is the maximum amount of non-matched lines accepted
			 within a matched range. This goes from 21 in small files to 9 in large files */

		range_tolerance = 21 - floor(wfpcount / 21);
		if (range_tolerance < 9)
			range_tolerance = 9;

		/* Min matched lines is the number of matched lines in total under which the result
			 is ignored. This goes from 3 in small files to 10 in large files */

		min_match_lines = 3 + floor(wfpcount / 5);
		if (min_match_lines > 10)
			min_match_lines = 10;
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
	uint8_t *ptr = (uint8_t *)&wfpint32;
	out[0] = ptr[3];
	out[1] = ptr[2];
	out[2] = ptr[1];
	out[3] = ptr[0];
}


static void matchmap_setup(scan_data_t * scan)
{
	char * matchmap_env = getenv("SCANOSS_MATCHMAP_MAX");
	if (matchmap_env)
	{
		int matchmap_max_files_aux = atoi(matchmap_env);
		if (matchmap_max_files_aux > MAX_MATCHMAP_FILES / 4 &&  matchmap_max_files_aux < MAX_MATCHMAP_FILES * 20)
		{
			scanlog("matchmap size changed by env variable to: %d\n", matchmap_max_files_aux);
			matchmap_max_files = matchmap_max_files_aux;
		}
	}
	//If we are looking fow multiple snippets, update the matchmap size
	matchmap_max_files = scan->max_snippets_to_process * matchmap_max_files;
	
	if (engine_flags & ENABLE_HIGH_ACCURACY)
	{
		matchmap_max_files *=5;
		scanlog("matchmap size changed by high accuracy analisys to: %d\n", matchmap_max_files);
	}
	scan->matchmap = calloc(matchmap_max_files, sizeof(matchmap_entry));
}

typedef struct  matchmap_entry_t
{
	uint8_t * md5_set;
	uint32_t line;
	uint8_t wfp[WFP_LN];
	uint32_t size; 
} matchmap_entry_t;

/**
 * @brief Add one new md5 to the matchmap
 * @param scan pointer to scan object
 * @param item new item to be added in the matchmap
 * @param look_from Index to start to look for the position
 * @param max_hit External variable to keep the max_hits
 * @param max_hit_pos External variable to keep the index of the max hit
 */

int add_file_to_matchmap(scan_data_t *scan, matchmap_entry_t *item, uint8_t *md5, int look_from, int *max_hit, int *max_hit_pos)
{
	/* Check if md5 already exists in map */
	int found = -1;
	int start_pos = look_from < 0 ? 0 : look_from;
	uint8_t *lastwfp = NULL;
	/* Travel the matchmap from the starting point*/
	for (long t = start_pos; t < scan->matchmap_size; t++)
	{
		//The matchmap is sorted, stop if you are comparing against a different sector
		if (*scan->matchmap[t].md5 > *md5 && (scan->matchmap_size < matchmap_max_files))
		{
			scanlog("skipping: md5 out of range wfp\n");
			return -1;
		}
		
		if (md5cmp(scan->matchmap[t].md5, md5))
		{
			lastwfp = scan->matchmap[t].lastwfp;
			found = t;
			/* Skip if we are hitting the same wfp again for this file) */
			if (!memcmp(item->wfp, lastwfp, 4))
			{
				//scanlog("skipping hit on %d: repeated wfp: %02x%02x%02x%02x\n", t, lastwfp[0],lastwfp[1],lastwfp[2],lastwfp[3]);
			}
			else
			{
				scan->matchmap[found].hits++;
				if (scan->matchmap[found].hits > *max_hit)
				{
					*max_hit_pos = t;
					*max_hit = scan->matchmap[found].hits;
					// scanlog("hit max = %d at %d\n", hit_max, t);
				}
			}

			break;
		}
	}

	if (found < 0)
	{
		/* Not found. Add MD5 to map */
		if (scan->matchmap_size >= matchmap_max_files)
		{
			scanlog("skipping: matchmap is full\n");
			return -1;
		}

		found = scan->matchmap_size;

		/* Clear row */
		memset(scan->matchmap[found].md5, 0, map_rec_len);

		/* Write MD5 */
		memcpy(scan->matchmap[found].md5, md5, MD5_LEN);
	}

	/* Search for the right range */

	uint32_t from = 0, to = 0;
	uint16_t oss_line = uint16_read(md5 + MD5_LEN);

	for (uint32_t t = 0; t < MATCHMAP_RANGES; t++)
	{
		from = scan->matchmap[found].range[t].from;
		to = scan->matchmap[found].range[t].to;

		int gap = abs(from - item->line);

		/* New range */
		if (!from && !to)
		{
			/* Update from and to */
			scan->matchmap[found].range[t].from = item->line;
			scan->matchmap[found].range[t].to = item->line;
			scan->matchmap[found].range[t].oss_line = oss_line;
			break;
		}

		/* Another hit in the same line, no need to expand range */
		else if (from == item->line)
		{
			break;
		}

		/* Increase range */
		else if (gap < range_tolerance)
		{
			/* Update range start (from) */
			if (item->line < scan->matchmap[found].range[t].from)
			{
				scan->matchmap[found].range[t].from = item->line;
				scan->matchmap[found].range[t].oss_line = oss_line;
			}
			else if (item->line > scan->matchmap[found].range[t].to)
				scan->matchmap[found].range[t].to = item->line;

			break;
		}
	}

	/* Update last wfp */
	if (lastwfp)
		memcpy(lastwfp, item->wfp, WFP_LN);

	if (found == scan->matchmap_size)
		scan->matchmap_size++;
	return 0;
}

match_t ldb_scan_snippets(scan_data_t *scan)
{

	scanlog("ldb_scan_snippets\n");
	if (!scan->hash_count)
	{
		scanlog("No hashes return NONE\n");
		return MATCH_NONE;
	}

	if (engine_flags & DISABLE_SNIPPET_MATCHING)
		return MATCH_NONE;

	if (trace_on)
		scanlog("Checking snippets. Traced (-qi) matches marked with *\n");
	else
		scanlog("Checking snippets\n");

	matchmap_setup(scan);
	adjust_tolerance(scan);

	/* First build a map with all the MD5s related with each WFP from the source file*/

	matchmap_entry_t map[scan->hash_count];
	int map_max_size = 0;
	for (long i = 0; i < scan->hash_count; i++)
	{
		/* Get all file IDs for given wfp */
		map[i].md5_set = malloc(WFP_REC_LN * MATCHMAP_ITEM_SIZE);
		wfp_invert(scan->hashes[i], map[i].wfp);
		//scanlog(" Add wfp %02x%02x%02x%02x to map\n",map[i].wfp[0], map[i].wfp[1],map[i].wfp[2],map[i].wfp[3]);
		uint32_write(map[i].md5_set, 0);
		map[i].line = scan->lines[i];
		ldb_fetch_recordset(NULL, oss_wfp, map[i].wfp, false, get_all_file_ids, (void *)map[i].md5_set);
		map[i].size = uint32_read(map[i].md5_set) / WFP_REC_LN;
		if (map[i].size > map_max_size)
			map_max_size = map[i].size;
		
	}
	
	/* Classify the WFPs in cathegories depending on popularity
	Each cathegoy will contain a sub set of index refered to map rows*/
	#define MAP_INDIRECTION_CAT_NUMBER 1000
	#define MAP_INDIRECTION_CAT_SIZE (map_max_size / (MAP_INDIRECTION_CAT_NUMBER-1))
	int map_indedirection_items_size = scan->hash_count / (MAP_INDIRECTION_CAT_NUMBER / 10) < 10 ? 
													scan->hash_count : 
													scan->hash_count / (MAP_INDIRECTION_CAT_NUMBER / 10);

	int map_indirection[MAP_INDIRECTION_CAT_NUMBER][map_indedirection_items_size]; //define the cathegories
	int map_indirection_index[MAP_INDIRECTION_CAT_NUMBER]; //index for each cathegory
	
	memset(map_indirection, 0, sizeof(map_indirection));
	memset(map_indirection_index, 0, sizeof(map_indirection_index));

	scanlog ("< Snippet scan setup: Map size = %d, Cat N = %d, Cat size = %d >\n", map_max_size, MAP_INDIRECTION_CAT_NUMBER, MAP_INDIRECTION_CAT_SIZE);

	for (int i =0; i < scan->hash_count; i++)
	{
		int cat = map[i].size / (MAP_INDIRECTION_CAT_SIZE+1);
		
		if (map_indirection_index[cat] >= map_indedirection_items_size)
		{
			scanlog("Cat %d is full, skiping...\n", cat);
			continue;
		}

		map_indirection[cat][map_indirection_index[cat]] = i;
		map_indirection_index[cat]++;
	}

	/* Calculate a limit to the quantity of cathegories to be processed, 
	the cathegoies with less quantity of MD5s (less popular) will be prioritased*/
	int cat_limit = 0;
	int cat_limit_index=0;
	
	for (int i = 0; i < MAP_INDIRECTION_CAT_NUMBER; i++)
	{
		bool exit = false;
		for (int j=0; j < map_indirection_index[i]; j++)
		{
			cat_limit += map[map_indirection[i][j]].size;
			if (cat_limit > matchmap_max_files)
			{
				cat_limit_index = i;
				exit = true;
				break;
			}
		}
		if (exit)
			break;
		else
			cat_limit_index = i+1;
	}
	
	if (debug_on)
	{
		scanlog("Cathegories result:\n");
		for (int i = 0; i < MAP_INDIRECTION_CAT_NUMBER; i++)
		{
			for (int j=0; j < map_indirection_index[i]; j++)
			{
				 uint8_t * wfp = map[map_indirection[i][j]].wfp;
				scanlog("Cat :%d - item %d line %d - %02x%02x%02x%02x - size %d\n",i,j, 
						map[map_indirection[i][j]].line, wfp[0], wfp[1],wfp[2],wfp[3], map[map_indirection[i][j]].size);
			}
		}
	}

	scanlog("Map limit on %d MD5s at  %d of %d\n",cat_limit, cat_limit_index, MAP_INDIRECTION_CAT_NUMBER);

	int map_indexes[scan->hash_count];
	memset(map_indexes, 0, sizeof(map_indexes));

	/*Add MD5s to the matchmap, sorting by sector. First add the MD5s starting with 00, then with 01 and so on*/
	int last_sector_aux = 0;
	for (int  sector = 0; sector < 256; sector++)
	{
		scan->matchmap_rank_by_sector[sector] = -1;
		int sector_max = min_match_hits;
		for (int cat = 0; cat < cat_limit_index; cat++)
		{
			/* travel the cathegories map*/
			for (int item_in_cat = 0; item_in_cat < map_indirection_index[cat]; item_in_cat++)
			{
				int i = map_indirection[cat][item_in_cat];
				uint8_t *md5s = map[i].md5_set + 4;
				/* Add each item to the matchmap*/
				for (int wfp_index = map_indexes[i]; wfp_index < map[i].size; wfp_index++)
				{
					int wfp_p = wfp_index * WFP_REC_LN;
					/*Stop when a new sector appers*/
					if (md5s[wfp_p] != sector)
					{
						map_indexes[i] = wfp_index;
						break;
					}

					add_file_to_matchmap(scan, &map[i], &md5s[wfp_p], last_sector_aux, &sector_max, &scan->matchmap_rank_by_sector[sector]);
				}
			}	
		}
		/*start to look from the last added md5*/
		last_sector_aux = scan->matchmap_size - 1;
	}
	
	/* Check if we have at least one possible match*/
	bool at_least_one_possible_match = false;
	for (int sector = 0; sector < 255; sector++)
	{
		if (scan->matchmap_rank_by_sector[sector] > -1)
		{
			if (scan->matchmap[scan->matchmap_rank_by_sector[sector]].hits > 0)
			{
				at_least_one_possible_match = true;
			}
		}
	}

	if (debug_on)
	{
		scanlog("First Stage - Max hits by sector\n");
		for (int sector = 0; sector < 255; sector++)
		{
			if (scan->matchmap_rank_by_sector[sector] >= 0)
				scanlog("Sector %02x, Max at %d with %d\n", sector, scan->matchmap_rank_by_sector[sector], scan->matchmap[scan->matchmap_rank_by_sector[sector]].hits);
		}
	}

	if (!at_least_one_possible_match)
	{
		scanlog("No sector with hits, no match\n");	
	}
	/* Second state scan, using the rest of the availbles MD5s from the map*/
	else
	{
		scanlog("-- Second Stage: Looking on the rest of the cathegories -- \n");
		for (int cat = cat_limit_index; cat < MAP_INDIRECTION_CAT_NUMBER ; cat++)
		{
			/* travel the cathegories map*/
			for (int item_in_cat = 0; item_in_cat < map_indirection_index[cat]; item_in_cat++)
			{
				int i = map_indirection[cat][item_in_cat];
				uint8_t *md5s = map[i].md5_set + 4;
				/* Add each item to the matchmap*/
				for (int wfp_index = map_indexes[i]; wfp_index < map[i].size; wfp_index++)
				{
					int wfp_p = wfp_index * WFP_REC_LN;
					int sector = md5s[wfp_p];
					int sector_max = min_match_hits;

					if (scan->matchmap_rank_by_sector[sector] < 0)
						continue;
					else if (scan->matchmap_rank_by_sector[sector] >= 0 )
						sector_max = scan->matchmap[scan->matchmap_rank_by_sector[sector]].hits;

					if (md5cmp(&md5s[wfp_p], scan->matchmap[scan->matchmap_rank_by_sector[sector]].md5))
					{				 
						add_file_to_matchmap(scan, &map[i], &md5s[wfp_p], 0, &sector_max, &scan->matchmap_rank_by_sector[sector]);
					}
				}
			}	
		}
	}

	//for debuging
	if (debug_on)
	{
		scanlog("Max hits by sector\n");
		for (int sector = 0; sector < 255; sector++)
		{
			if (scan->matchmap_rank_by_sector[sector] >= 0)
				scanlog("Sector %02x, Max at %d with %d\n", sector, scan->matchmap_rank_by_sector[sector], scan->matchmap[scan->matchmap_rank_by_sector[sector]].hits);
		}
	}

	//Free memory
	for (int i = 0; i  < scan->hash_count; i++)
	{
		free(map[i].md5_set);
	}
	
	if (scan->matchmap_size)
	 	return MATCH_SNIPPET;
	
	scanlog("Snippet scan has no matches\n");
	return MATCH_NONE;


}
