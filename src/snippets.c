/* SPDX-License-Identifier: GPL-2.0-or-later
*
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

#include "ignorelist.h"
#include "util.h"
#include "debug.h"
#include "limits.h"
#include "scanoss.h"
#include "ldb.h"
#include "decrypt.h"

/* Set map hits to zero for the given match */
void clear_hits(uint8_t *match)
{
	match[MD5_LEN] = 0;
	match[MD5_LEN + 1] = 0;
}

int path_depth(uint8_t *path, int len)
{
	int depth = 0;
	for (int i = 0; i < len ; i++) if (path[i] == '/') depth++;
	return depth;
}

/* Recordset handler function to find shortest path */
static bool shortest_path_handler(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	int *shortest = (int *) ptr;
	if (datalen)
	{
		decrypt_data(data, datalen, "file", key, subkey);
		int depth = path_depth(data, datalen - MD5_LEN);
		if (depth < 1) return false;

		if (!*shortest)
			*shortest = depth;
		else if (depth < *shortest)
			*shortest = depth;
	}
	return false;
}

/* Returns the length of the shortest path among files matching md5 */
int get_shortest_path(uint8_t *md5)
{
	/* Direct component match has a top priority */
	if (ldb_key_exists(oss_url, md5)) return 1;

	int *shortest = calloc(1, sizeof(int));
	ldb_fetch_recordset(NULL, oss_file, md5, false, shortest_path_handler, (void *) shortest);

	int out = *shortest;
	free(shortest);

	return out;
}

/* If we have snippet matches, select the one with more hits (and shortest file path) */
uint8_t *biggest_snippet(scan_data *scan)
{
	uint8_t *out = NULL;
	int hits = 0;

	while (true)
	{
		int most_hits = 0;
		int shortest_path = 0;

		/* Select biggest snippet */
		for (int i = 0; i < scan->matchmap_size; i++)
		{
			hits = scan->matchmap[i].hits;

			if (hits < most_hits) continue;

			/* Calculate length of shortest path */
			int shortest = get_shortest_path(scan->matchmap[i].md5);
			bool shorter = false;
			if (shortest && shortest < shortest_path)
			{
				shorter = true;
				shortest_path = shortest;
			}

			/* Select match if hits is greater, or equal and shorter path */
			if ((hits > most_hits) || (hits == most_hits && shorter))
			{
				most_hits = hits;
				out = scan->matchmap[i].md5;

				/* reset shortest_path in case we have > most_hits */
				shortest_path = shortest;
			}
		}

		scanlog("Biggest snippet: %d\n", most_hits);
		scanlog("File path len: %d\n", shortest_path);

		if (most_hits < min_match_hits)
		{
			scan->match_type = none;
			scanlog("Not reaching min_match_hits\n");
			return NULL;
		}

		if (!hits) break;

		/* Erase match from map if MD5 is orphan (no files/components found) */
		if (shortest_path == MAX_PATH) clear_hits(out); else break;
	}

	scan->match_ptr = out;
	return out;
}

/* Handler function to collect all file ids */
static bool get_all_file_ids(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	uint8_t *record = (uint8_t *) ptr;
	if (datalen)
	{
		uint32_t size = uint32_read(record);

		/* End recordset fetch if MAX_QUERY_RESPONSE is reached */
		if (size + datalen + 4 >= MAX_QUERY_RESPONSE) return true;

		/* End recordset fetch if MAX_FILES are reached for the snippet */
		if ((WFP_REC_LN * MAX_FILES) <= (size + datalen)) return true;

		/* Save data and update dataln */
		memcpy(record + size + 4, data, datalen);
		uint32_write(record, size + datalen);
	}
	return false;
}

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

void add_snippet_ids(scan_data *scan, long from, long to)
{
	int maxlen = MAX_SNIPPET_IDS_RETURNED * WFP_LN * 2 + MATCHMAP_RANGES;
	bool found = false;

	/* Walk scan->lines array */
	for (int i = 0; i < scan->hash_count; i++)
	{
		if (scan->lines[i] > to - 1) break;

		/* If line is within from and to, add snippet id to list */
		if (scan->lines[i] >= from - 1)
		{
			found = true;

			char hex[9] = "\0";
			hex[8] = 0;
			uint32_t hash = scan->hashes[i];
			uint32_reverse((uint8_t *)&hash);
			ldb_bin_to_hex((uint8_t *)&hash, WFP_LN, hex);

			if (strlen(scan->snippet_ids) + WFP_LN * 2 + 1 >= maxlen) break;
			sprintf(scan->snippet_ids + strlen(scan->snippet_ids), "%s", hex);
		}
	}

	if (found) strcat(scan->snippet_ids, ",");
}

/* Compiles list of line ranges, returning total number of hits (lines matched) */
uint32_t compile_ranges(scan_data *scan) {

	*scan->line_ranges = 0;
	*scan->oss_ranges = 0;
	*scan->snippet_ids = 0;

	uint16_t reported_hits = uint16_read(scan->match_ptr + MD5_LEN);
	if (reported_hits < 2) return 0;

	/* Lowest tolerance simply requires selecting the higher match count */
	if (min_match_lines == 1)
	{
		strcpy(scan->line_ranges, "N/A");
		strcpy(scan->oss_ranges, "N/A");
		return uint16_read(scan->match_ptr + MD5_LEN);
	}

	/* Revise hits and decrease if needed */
	for (uint32_t i = 0; i < MATCHMAP_RANGES; i++)
	{
		long from     = uint16_read(scan->match_ptr + MD5_LEN + 2 + i * 6);
		long to       = uint16_read(scan->match_ptr + MD5_LEN + 2 + i * 6 + 2);
		long delta = to - from;

		if (to < 1) break;

		/* Ranges to be ignored (under min_match_lines) should decrease hits counter */
		if (delta < min_match_lines)
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

	/* Count matched lines */
	for (uint32_t i = 0; i < MATCHMAP_RANGES; i++)
	{

		long from     = uint16_read(scan->match_ptr + MD5_LEN + 2 + i * 6);
		long to       = uint16_read(scan->match_ptr + MD5_LEN + 2 + i * 6 + 2);
		long oss_from = uint16_read(scan->match_ptr + MD5_LEN + 2 + i * 6 + 4);

		scanlog("compile_ranges #%d = %ld to %ld\n", i, from, to);

		/* Determine if this is the last (first) range */
		bool first_range = false;
		if (i == MATCHMAP_RANGES) first_range = true;
		else if (!uint16_read(scan->match_ptr + MD5_LEN + 2 + (i + 1) * 6 + 2)) first_range = true;

		if (to < 1) break;

		/* Add range as long as the minimum number of match lines is reached */
		if ((to - from) >= min_match_lines)
		{
			add_snippet_ids(scan, from, to);

			/* Add tolerance to end of last range */
			if (!i)
			{
				to += range_tolerance;
				if (to > scan->total_lines) to = scan->total_lines;
			}

			/* Add tolerance to start of first range */
			if (first_range)
			{
				from -= range_tolerance;
				if (from < 1) from = 1;
			}

			sprintf (scan->line_ranges + strlen(scan->line_ranges), "%ld-%ld,", from, to);
			sprintf (scan->oss_ranges + strlen(scan->oss_ranges), "%ld-%ld,", oss_from, to - from + oss_from);
			hits += (to - from);
		}
	}

	/* Remove last comma */
	if (strlen(scan->snippet_ids) > 0) scan->snippet_ids[strlen(scan->snippet_ids) - 1] = 0;

	if (strlen(scan->line_ranges) > 0) scan->line_ranges[strlen(scan->line_ranges) - 1] = 0;
	else strcpy(scan->line_ranges, "all");

	if (strlen(scan->oss_ranges) > 0) scan->oss_ranges[strlen(scan->oss_ranges) - 1] = 0;
	else strcpy(scan->oss_ranges, "all");

	return hits;
}

static void adjust_tolerance(scan_data *scan)
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

/* Get inverted wfp from int32 */
void wfp_invert(uint32_t wfpint32, uint8_t *out)
{
	uint8_t *ptr = (uint8_t*)&wfpint32;
	out[0]=ptr[3];
	out[1]=ptr[2];
	out[2]=ptr[1];
	out[3]=ptr[0];
}

/* Add line hit to all files */
void add_popular_snippet_to_matchmap(scan_data *scan, uint32_t line, uint32_t min_tolerance)
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

void add_files_to_matchmap(scan_data *scan, uint8_t *md5s, uint32_t md5s_ln, uint8_t *wfp, uint32_t line, uint32_t min_tolerance)
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
			if (scan->matchmap_size >= MAX_FILES) continue;

			found = scan->matchmap_size;

			/* Clear row */
			memset(scan->matchmap[found].md5, 0, map_rec_len);

			/* Write MD5 */
			memcpy(scan->matchmap[found].md5, scan->md5, MD5_LEN);
		}

		/* Search for the right range */
		uint8_t *lastwfp = scan->matchmap[found].lastwfp;

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
				/* Update hits count (if we are not hitting the same wfp again) */
				if (memcmp(wfp,lastwfp,4))
				{
					scan->matchmap[found].hits++;
					memcpy(lastwfp,wfp,4);
				}
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

		if (found == scan->matchmap_size) scan->matchmap_size++;
	}
}

/*	Query all wfp and add resulting file ids to the matchmap
		Scan is done from last to first line, because headers and
		first lines are statistically more common than the end of
		the file */
matchtype ldb_scan_snippets(scan_data *scan) {

	if (!scan->hash_count) return none;

	if (engine_flags & DISABLE_SNIPPET_MATCHING) return none;

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
			add_popular_snippet_to_matchmap(scan, line, last_line - line);
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

	if (scan->matchmap_size) return snippet;
	scanlog("Snippet scan has no matches\n");
	return none;
}
