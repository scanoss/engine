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
  @file snippets_selection.c
  @date 30 Sep 2025
  @brief Contains the functions used for  snippets processing

  Long description // TODO
  @see https://github.com/scanoss/engine/blob/master/src/scan.c
 */


#include "decrypt.h"
#include "file.h"
#include "match.h"
#include "match_list.h"
#include "stdlib.h"
#include "snippets.h"
#include "ignorelist.h"

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
	/* candidates selected by their wfp1 evidence rank first */
	if (a->wfp1_evidence != b->wfp1_evidence)
		return b->wfp1_evidence;
	if (match_selection_hits(a) <= match_selection_hits(b))
		return true;
	else
		return false;
}

bool ranges_intersection(match_data_t *a, match_data_t *b)
{
	for (int i = 0; i < a->matchmap_reg->ranges_number; i++)
	{
		for (int j = 0; j < b->matchmap_reg->ranges_number; j++)
		{
			if (a->matchmap_reg->range[i].from <= b->matchmap_reg->range[j].to &&
				b->matchmap_reg->range[j].from <= a->matchmap_reg->range[i].to)
				return true;
		}
	}
	return false;
}

/* Matched lines as a percent of the scanned file (1 to 99) */
static int lines_matched_percent(int matched_lines, int total_lines)
{
	float percent = (matched_lines * 100) / total_lines;
	int matched_percent = floor(percent);
	if (matched_percent > 99)
		matched_percent = 99;
	if (matched_percent < 1)
		matched_percent = 1;
	return matched_percent;
}

static void snippet_wfp1_evidence(scan_data_t *scan, match_data_t *match);

/**
 * @brief Fill the matches list array based on the matchmap. The possible matches will be sorted by hits number.
 *
 * @param scan
 */
/**
 * @brief Build a snippet match from one ranked matchmap entry, applying the
 *        acceptance criteria (min hits, file extension, min matched lines).
 * @param scan current scan
 * @param j matchmap index
 * @return the match, or NULL when the entry does not qualify
 */
static match_data_t *snippet_candidate_build(scan_data_t *scan, int j)
{
	if (scan->matchmap[j].hits < scan->snippet_min_hits) /* Only consider file with more than min_match_hits */
		return NULL;

	match_data_t *match_new = calloc(1, sizeof(match_data_t)); /* Create a match object */
	if (!match_new)
	{
		scanlog("Error allocating memory for match data\n");
		return NULL;
	}
	memcpy(match_new->file_md5, scan->matchmap[j].md5, oss_file.key_ln);
	match_new->hits = scan->matchmap[j].hits;
	match_new->matchmap_reg = &scan->matchmap[j];
	match_new->type = scan->match_type;
	strcpy(match_new->source_md5, scan->source_md5);
	match_new->scan_ower = scan;

	if (scan->snippet_honor_file_extension && snippet_extension_discard(match_new))
	{
		match_data_free(match_new);
		return NULL;
	}

	int matched_lines = compile_ranges(match_new);
	if (matched_lines < scan->snippet_min_lines)
	{
		match_data_free(match_new);
		return NULL;
	}

	match_new->matched_percent = lines_matched_percent(matched_lines, match_new->scan_ower->total_lines);
	match_new->lines_matched = matched_lines;
	snippet_wfp1_evidence(scan, match_new);
	return match_new;
}

/**
 * @brief Tell whether the current matchmap yields at least one snippet match,
 *        using the same acceptance criteria as biggest_snippet(). Leaves the
 *        scan state untouched. Must only be called after a snippet pass that
 *        returned MATCH_SNIPPET (matchmap_rank_by_sector initialized).
 * @param scan current scan
 * @return true if some matchmap file qualifies as a snippet match
 */
bool snippet_has_candidate(scan_data_t *scan)
{
	/* compile_ranges() forces snippet_adjust_tolerance on; restore it so a
	   following snippet pass keeps the caller's tolerance configuration. */
	bool adjust_tolerance = scan->snippet_adjust_tolerance;
	bool found = false;

	for (int sector = 0; sector < 256 && !found; sector++)
	{
		int j = scan->matchmap_rank_by_sector[sector];
		if (j < 0)
			continue;
		match_data_t *m = snippet_candidate_build(scan, j);
		if (m)
		{
			found = true;
			match_data_free(m);
		}
	}

	scan->snippet_adjust_tolerance = adjust_tolerance;
	return found;
}

void biggest_snippet(scan_data_t *scan)
{
	scanlog("biggest_snippet\n");
	/*Initialize the auxiliary indirection list */
	for (int i = 0; i < scan->max_snippets_to_process; i++)
		scan->matches_list_array_indirection[i] = -1;

	/*Fill the matches list with the files from the matchmap */
	for (int sector = 0; sector < 256; sector++)
	{
		int j = scan->matchmap_rank_by_sector[sector];
		
		if (j < 0)
			continue;
		
		match_data_t *match_new = snippet_candidate_build(scan, j);
		if (match_new)
		{
			int i = 0;
			scanlog_snippet_origin("Snippet candidate", match_new);
			//match_new->hits = hits;

			/* Place the match in the list of the snippet region it belongs to.
			 * First look for an existing list whose ranges intersect this match
			 * (same region -> alternative candidate). If none intersects, open a
			 * new list for this region while there is room; otherwise fall back to
			 * the last list. */
			bool assigned = false;
			for (i = 0; i < scan->matches_list_array_index; i++)
			{
				if (match_list_eval(scan->matches_list_array[i], match_new, ranges_intersection))
				{
					if (!match_list_add(scan->matches_list_array[i], match_new, hit_test, true))
						match_data_free(match_new);
					assigned = true;
					break;
				}
			}

			if (!assigned)
			{
				if (scan->matches_list_array_index < scan->max_snippets_to_process)
				{
					/* New non-overlapping region: create its own list and add the match there */
					int new_index = scan->matches_list_array_index;
					scan->matches_list_array[new_index] = match_list_init(true, 1);
					scan->matches_list_array_index++;
					if (!match_list_add(scan->matches_list_array[new_index], match_new, hit_test, true))
						match_data_free(match_new);
				}
				else
				{
					/* No room left for new regions: force into the last list */
					if (!match_list_add(scan->matches_list_array[scan->max_snippets_to_process - 1], match_new, hit_test, true))
						match_data_free(match_new);
				}
			}
		}
	}
	/*just for loging*/
	if (debug_on)
	{
		scanlog("Match list array index: %d\n", scan->matches_list_array_index);
		for (int i = 0; i < scan->matches_list_array_index; i++)
		{
			scanlog("Match list N %d, with %d matches. %d <= HITS <= %d \n", i, scan->matches_list_array[i]->items,
					scan->matches_list_array[i]->last_element->match->hits,
					scan->matches_list_array[i]->headp.lh_first->match->hits);
			struct entry *item = NULL;
			LIST_FOREACH(item, &scan->matches_list_array[i]->headp, entries)
			{
				char md5_hex[oss_file.key_ln * 2 + 1];
				ldb_bin_to_hex(item->match->file_md5, oss_file.key_ln, md5_hex);
				scanlog("%s - %d (origin=%s)\n", md5_hex, item->match->hits, snippet_origin(item->match->matchmap_reg));
			}
		}
	}
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
int ranges_assemble(matchmap_range *ranges, char *line_ranges, char *oss_ranges, int min_range_lines, int ranges_number)
{
	int out = 0;
	/* Walk ranges */
	for (int i = 0; i < ranges_number; i++)
	{
		int to = ranges[i].to;
		int from = ranges[i].from;
		int oss = ranges[i].oss_line;
		
		if ((from || to) && oss)
		{
			if (from == 0)
				from = 1;
			//discard snippets below the limit of detection
			if (to - from < min_range_lines)
				continue;
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
matchmap_range * ranges_join_overlapping(matchmap_range *ranges, int size, int range_tolerance, bool dynamic_ranges)
{
	int out_size = MATCHMAP_RANGES;
	if (dynamic_ranges)
		out_size = size;

	matchmap_range *out_ranges = calloc(out_size, sizeof(matchmap_range));
	if (!out_ranges)
		return NULL;

	int processed = 0;
	int tolerance = range_tolerance > 0 ? range_tolerance : 1;
	while (processed < size && tolerance < range_tolerance * 20)
	{
		int out_ranges_index = -1;
		processed = 0;
		memset(out_ranges, 0, sizeof(matchmap_range) * out_size);
		scanlog("Range tolerance: %d\n", tolerance);
		for (int i = 0; i < size; i++)
		{
			if (ranges[i].from && ranges[i].to)
			{
				if(out_ranges_index >= 0 && (ranges[i].from - tolerance <= out_ranges[out_ranges_index].to))
				{
					if (out_ranges[out_ranges_index].to > ranges[i].to)
						continue;

					out_ranges[out_ranges_index].to = ranges[i].to;
					//scanlog("join range %d with %d: %d - %d\n", i, out_ranges_index, out_ranges[out_ranges_index].from, out_ranges[out_ranges_index].to);
				}
				else
				{
					out_ranges_index++;
					if (out_ranges_index == MATCHMAP_RANGES && !dynamic_ranges)
						break;
					out_ranges[out_ranges_index].from = ranges[i].from;
					out_ranges[out_ranges_index].to = ranges[i].to;
					out_ranges[out_ranges_index].oss_line = ranges[i].oss_line;	
				}
				processed++;
			}
		}
		if (dynamic_ranges)
			break;
		tolerance *= 2;
	}	

	return out_ranges;
}

/**
 * @brief Remove empty ranges, shifting remaining ranges
 *
 * @param ranges ranges list to process
 */
void ranges_sort(matchmap_range *ranges, int size)
{
	qsort(ranges, size, sizeof(matchmap_range), range_comp);
}

/**
 * @brief Compiles list of line ranges, returning total number of hits (lines matched)
 *
 * @param scan point to scan data to process
 * @return uint32_t snippet hits
 */
uint32_t compile_ranges(match_data_t *match)
{
	if (match->matchmap_reg->ranges_number <= 0)
	{
		scanlog("No ranges to compile\n");
		return 0;
	}
	char line_ranges[MAX_FIELD_LN * 2] = "\0";
	char oss_ranges[MAX_FIELD_LN * 2] = "\0";
	char snippet_ids[MAX_SNIPPET_IDS_RETURNED * WFP_LN * 2 + MATCHMAP_RANGES + 1] = "\0";
	if (!match->matchmap_reg)
	{
		scanlog("compile ranges fail");
		return 0;
	}

	int hits = 0;
	/* Add tolerances and assemble line ranges */
	ranges_sort(match->matchmap_reg->range, match->matchmap_reg->ranges_number);

	if (debug_on)
	{
		scanlog("Accepted ranges (min lines range = %d):\n", match->scan_ower->snippet_min_lines);
		for (uint32_t i = 0; i < match->matchmap_reg->ranges_number; i++)
		{
			if ( match->matchmap_reg->range[i].from && match->matchmap_reg->range[i].to)
				scanlog("	%d = %u to %u - OSS from: %d\n", i, match->matchmap_reg->range[i].from,match->matchmap_reg->range[i].to, 
																match->matchmap_reg->range[i].oss_line);
		}
	}
	//TODO: Re-enable dynamic ranges when feature is complete
	// For now, we force adjust_tolerance to ensure stable behavior
	match->scan_ower->snippet_adjust_tolerance = true;
	scanlog("Snippet adjust tolerance flag is being ignored\n");
	matchmap_range *ranges = ranges_join_overlapping(match->matchmap_reg->range,  match->matchmap_reg->ranges_number, match->scan_ower->snippet_range_tolerance, !match->scan_ower->snippet_adjust_tolerance);
	int ranges_number = !match->scan_ower->snippet_adjust_tolerance ? match->matchmap_reg->ranges_number : MATCHMAP_RANGES;
	if (engine_flags & ENABLE_SNIPPET_IDS)
	{
		for (int range = 0; range < ranges_number; range++)
		{
			if (!ranges[range].from && !ranges[range].to)
				break;
			
			add_snippet_ids(match, snippet_ids, ranges[range].from,  ranges[range].to); //TODO
		}
	}
		
	if (debug_on)
	{
		scanlog("Final ranges:\n");
		for (uint32_t i = 0; i < ranges_number; i++)
		{
		if ( ranges[i].from && ranges[i].to)
				scanlog("	%d = %u to %u - OSS from: %u\n", i, ranges[i].from, ranges[i].to, ranges[i].oss_line);
		}
	}
	hits = ranges_assemble(ranges, line_ranges, oss_ranges, match->scan_ower->snippet_min_lines, ranges_number);
	match->line_ranges = strdup(line_ranges);
	match->oss_ranges = strdup(oss_ranges);
	match->snippet_ids = strdup(snippet_ids);
	free(ranges);

	return hits;
}


/**
 * @brief Matched lines of a set of ranges, counted as compile_ranges() does
 *        (sort, join overlapping ranges, discard ranges under the minimum).
 */
static int ranges_matched_lines(scan_data_t *scan, matchmap_range *ranges, int ranges_number)
{
	if (ranges_number <= 0)
		return 0;
	ranges_sort(ranges, ranges_number);
	matchmap_range *joined = ranges_join_overlapping(ranges, ranges_number, scan->snippet_range_tolerance, false);
	if (!joined)
		return 0;
	char line_ranges[MAX_FIELD_LN * 2] = "\0";
	char oss_ranges[MAX_FIELD_LN * 2] = "\0";
	int lines = ranges_assemble(joined, line_ranges, oss_ranges, scan->snippet_min_lines, MATCHMAP_RANGES);
	free(joined);
	return lines;
}

/**
 * @brief Fill the wfp1 evidence of a snippet candidate, when it qualifies as a match with
 *        its wfp1 hits alone (min hits, min lines). A file the wfp2 pass did not touch
 *        has only wfp1 evidence; a file found by wfp2 alone has none.
 * @param scan current scan
 * @param match snippet candidate
 */
static void snippet_wfp1_evidence(scan_data_t *scan, match_data_t *match)
{
	matchmap_entry *entry = match->matchmap_reg;
	if (!entry->range_wfp1)
	{
		if (entry->hits_wfp2)
			return;
		match->wfp1_evidence = true;
		match->hits_wfp1 = match->hits;
		match->lines_matched_wfp1 = match->lines_matched;
		match->matched_percent_wfp1 = match->matched_percent;
		return;
	}

	int hits = entry->hits - entry->hits_wfp2;
	if (hits < scan->snippet_min_hits)
		return;
	int lines = ranges_matched_lines(scan, entry->range_wfp1, entry->ranges_number_wfp1);
	if (lines < scan->snippet_min_lines)
		return;
	match->wfp1_evidence = true;
	match->hits_wfp1 = hits;
	match->lines_matched_wfp1 = lines;
	match->matched_percent_wfp1 = lines_matched_percent(lines, scan->total_lines);
}

/**
 * @brief Origin of the snippet hits accumulated for one matchmap file.
 * @param entry matchmap entry
 * @return "wfp1", "wfp2" or "wfp1+wfp2"
 */
const char *snippet_origin(matchmap_entry *entry)
{
	if (!entry || !entry->hits_wfp2)
		return "wfp1";
	if (entry->hits_wfp2 >= entry->hits)
		return "wfp2";
	return "wfp1+wfp2";
}

/**
 * @brief Log the wfp1/wfp2 origin of a snippet match.
 * @param prefix text that identifies the log context
 * @param match snippet match
 */
void scanlog_snippet_origin(const char *prefix, match_data_t *match)
{
	if (!debug_on || !match || !match->matchmap_reg)
		return;
	matchmap_entry *e = match->matchmap_reg;
	char md5_hex[oss_file.key_ln * 2 + 1];
	ldb_bin_to_hex(match->file_md5, oss_file.key_ln, md5_hex);
	if (!e->hits_wfp2)
	{
		scanlog("%s %s: hits=%d (wfp1=%d, wfp2=%d), origin=%s\n", prefix, md5_hex,
				e->hits, e->hits - e->hits_wfp2, e->hits_wfp2, snippet_origin(e));
		return;
	}
	scanlog("%s %s: hits=%d (wfp1=%d, wfp2=%d), origin=%s, selected by %s evidence (hits=%d, lines=%d)\n", prefix, md5_hex,
			e->hits, e->hits - e->hits_wfp2, e->hits_wfp2, snippet_origin(e),
			match->wfp1_evidence ? "wfp1" : "total", match_selection_hits(match), match_selection_lines(match));
}
