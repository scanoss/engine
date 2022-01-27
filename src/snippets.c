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

int map_rec_len;

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
 * @brief Return the path depth
 * @param path path string
 * @param len path string len
 * @return path len, ie number of '/'
 */
int path_depth(uint8_t *path, int len)
{
	int depth = 0;
	for (int i = 0; i < len ; i++) if (path[i] == '/') depth++;
	return depth;
}

/**
 * @brief Recordset handler function to find shortest path. 
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

/**
 * @brief Returns the length of the shortest path among files matching md5
 * @param md5 MD5 pointer
 * @return lenght of shortest path
 */
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

/**
 * @brief Returns the length of the shortest path among files matching md5
 * @param md5 MD5 pointer
 * @return lenght of shortest path
 */
int get_match_popularity(uint8_t *md5, int setpoint)
{
	/* Direct component match has a top priority */
	if (!ldb_key_exists(oss_file, md5)) 
		return 0;

	int set = setpoint;
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
bool snippet_extension_discard(scan_data *scan, uint8_t *md5)
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
 * @brief If we have snippet matches, select the one with more hits (and shortest file path)
 * @param scan scan data pointer
 * @return pointer to selected match
 */
uint8_t *biggest_snippet(scan_data *scan)
{
	uint8_t *out = NULL;
	int hits = 0;
	int shortest_path = MAX_PATH;
	while (true)
	{
		int most_hits = 0;

		/* Select biggest snippet */
		for (int i = 0; i < scan->matchmap_size; i++)
		{
			hits = scan->matchmap[i].hits;

			if (hits < most_hits) continue;

			/* Select match if hits is greater, or equal and shorter path */
			if (hits > most_hits)
			{
				most_hits = hits;
				out = scan->matchmap[i].md5;
				char aux_hex[32];
				ldb_bin_to_hex(out,16,aux_hex);
				shortest_path = get_shortest_path(out);
				scanlog(" selected: %s - hits %d\n", aux_hex, hits);
			}
			else if (hits == most_hits)
			{
				int shortest_new = get_shortest_path(scan->matchmap[i].md5);

				int populatity = get_match_popularity(out, 0);
				int populatity_new = get_match_popularity(scan->matchmap[i].md5, populatity * 2);

				char aux_hex[33];
				ldb_bin_to_hex(out,16,aux_hex);

				char aux_hex2[33];
				ldb_bin_to_hex(scan->matchmap[i].md5,16,aux_hex2);

				scanlog("%s/%s - hits: %d- pop: %d/%d - short: %d/%d\n", aux_hex2, aux_hex, hits, populatity_new, populatity, shortest_new, shortest_path);

				if (populatity_new > populatity * 2 || (shortest_new && shortest_new < shortest_path))
				{
					out = scan->matchmap[i].md5;
					shortest_path = shortest_new;
				}			

			}
		}

		scanlog("Biggest snippet: %d\n", most_hits);
//		scanlog("File path len: %d\n", shortest_path);

		if (most_hits < min_match_hits)
		{
			scanlog("Not reaching min_match_hits\n");
			return NULL;
		}

		if (!hits) break;

		/* Erase match from map if MD5 is orphan (no files/components found) */
		if (shortest_path == MAX_PATH) clear_hits(out); else break;
	}

	if (snippet_extension_discard(scan, out)) return NULL;

	scan->match_ptr = out;
	return out;
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
		if ((WFP_REC_LN * MAX_FILES) <= (size + datalen)) return true;

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

/**
 * @brief Assemble line ranges from ranges into scan->line_ranges and oss_ranges
 * @param ranges input ranges list
 * @param scan[out] pointer to scan data
 * @return hits
 */
int ranges_assemble(matchmap_range *ranges, scan_data *scan)
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
			if (*scan->line_ranges) strcat(scan->line_ranges, ",");
			if (*scan->oss_ranges) strcat(scan->oss_ranges, ",");

			/* Add from-to values */
			sprintf (scan->line_ranges + strlen(scan->line_ranges), "%d-%d", from, to);
			sprintf (scan->oss_ranges + strlen(scan->oss_ranges), "%d-%d", oss, to - from + oss);

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
void ranges_add_tolerance(matchmap_range *ranges, scan_data *scan)
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

			ranges[i].from = from;
			ranges[i].to= to;
			ranges[i].oss_line = oss_from;
		}
	}

	/* Add tolerances and assemble line ranges */
	ranges_add_tolerance(ranges, scan);
	ranges_remove_empty(ranges);
	ranges_join_overlapping(ranges);
	hits = ranges_assemble(ranges, scan);
	free(ranges);

	/* Remove last comma */
	if (!scan->line_ranges) strcpy(scan->line_ranges, "all");
	if (!scan->oss_ranges)  strcpy(scan->oss_ranges, "all");

	return hits;
}

/**
 * @brief Ajust snippet match tolerance
 * @param scan pointer to scan data struct
 */
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

/**
 * @brief Add matchmap to scan structure
 * @param scan pointer to scan dats structure
 * @param md5s md5 list
 * @param md5s_ln md5 list lenght
 * @param wfp pointer t wfp
 * @param line line number
 * @param min_tolerance min tolerance
 */
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
