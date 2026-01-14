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

#include "limits.h"
#include "scanoss.h"
#include "ldb.h"
#include "snippets.h"

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
int matchmap_max_files = DEFAULT_MATCHMAP_FILES;

#define MATCHMAP_ITEM_SIZE (matchmap_max_files * 2)
static bool get_all_file_ids(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	uint8_t *record = (uint8_t *)ptr;

	if (data == NULL && datalen > 0)
	{
		scanlog("Error quering WFP table. datalen=%u but data is NULL\n", datalen);
		uint32_write(record,0);
		return true;
	}

	if (datalen)
	{
		uint32_t size = uint32_read(record);
		/* End recordset fetch if MAX_QUERY_RESPONSE is reached */
		if (size + datalen + 4 >= WFP_REC_LN * MATCHMAP_ITEM_SIZE)
		{
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

	return false;
}

/**
 * @brief Ajust snippet match tolerance
 * @param scan pointer to scan data struct
 */
static void adjust_tolerance(scan_data_t *scan)
{
	uint32_t wfpcount = scan->hash_count;
	int range_tolerance = SNIPPETS_DEFAULT_RANGE_TOLERANCE;  /** A maximum number of non-matched lines tolerated inside a matching range */
	int min_match_lines = SNIPPETS_DEFAULT_MIN_MATCH_LINES; /** Minimum number of lines matched for a match range to be acepted */
	int min_match_hits  = SNIPPETS_DEFAULT_MIN_MATCH_HITS;  /** Minimum number of snippet ID hits to produce a snippet match*/

	
	if (wfpcount && scan->lines[wfpcount - 1] > SNIPPETS_DEFAULT_MIN_MATCH_LINES * 2)
	{
		/* Range tolerance is the maximum amount of non-matched lines accepted
			 within a matched range. This goes from 21 in small files to 5 in large files */

		range_tolerance = 21 - floor(wfpcount / 21);
		if (range_tolerance < 5)
			range_tolerance = 5;

		/* Min matched lines is the number of matched lines in total under which the result
			 is ignored. This goes from 1 in small files to 10 in large files */

		min_match_lines = 5 + floor(wfpcount / 193);
		if (min_match_lines > 15)
			min_match_lines = 15;
		/* setup scan sensibility*/
		min_match_hits = 1 + floor(wfpcount / 19);
		if (min_match_hits > 9)
			min_match_hits = 9;
	}
	scan->snippet_min_hits = min_match_hits;
	scan->snippet_min_lines = min_match_lines;
	scan->snippet_range_tolerance = range_tolerance;
	scanlog("Match hits: %d, Tolerance: range=%d, lines=%d, wfpcount=%u\n", min_match_hits, range_tolerance, min_match_lines, wfpcount);
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

/**
 * @brief Setup matchmap size
 * @param scan current scan structure
 */
static void matchmap_setup(scan_data_t * scan)
{
	char * matchmap_env = getenv("SCANOSS_MATCHMAP_MAX");
	scan->max_matchmap_size = DEFAULT_MATCHMAP_FILES;
	if (matchmap_env)
	{
		int matchmap_max_files_aux = atoi(matchmap_env);
		if (matchmap_max_files_aux > DEFAULT_MATCHMAP_FILES / 4 &&  matchmap_max_files_aux < DEFAULT_MATCHMAP_FILES * 20)
		{
			scanlog("matchmap size changed by env variable to: %d\n", matchmap_max_files_aux);
			scan->max_matchmap_size = matchmap_max_files_aux;
		}
	}
	//If we are looking fow multiple snippets, update the matchmap size
	scan->max_matchmap_size *= scan->max_snippets_to_process;
	
	if (engine_flags & ENABLE_HIGH_ACCURACY)
	{
		scan->max_matchmap_size *=5;
		scanlog("matchmap size changed by high accuracy analisys to: %d\n", scan->max_matchmap_size);
	}
	matchmap_max_files = scan->max_matchmap_size;
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
		if (*scan->matchmap[t].md5 > *md5 && (scan->matchmap_size < scan->max_matchmap_size))
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
				//scanlog("hit %d at %d\n", scan->matchmap[found].hits, found);
				if (scan->matchmap[found].hits > *max_hit)
				{
					*max_hit_pos = t;
					*max_hit = scan->matchmap[found].hits;
				}
			}

			break;
		}
	}

	if (found < 0)
	{
		/* Not found. Add MD5 to map */
		if (scan->matchmap_size >= scan->max_matchmap_size)
		{
			scanlog("skipping: matchmap is full\n");
			return -1;
		}

		found = scan->matchmap_size;
		/* Write MD5 */
		memcpy(scan->matchmap[found].md5, md5, MD5_LEN);
		scan->matchmap[found].ranges_number = 0;	
	}

	/* Search for the right range */

	uint32_t from = 0;
	uint16_t oss_line = uint16_read(md5 + MD5_LEN);
	bool range_found = false;

	for (uint32_t t = 0; t < scan->matchmap[found].ranges_number; t++)
	{
		from = scan->matchmap[found].range[t].from;
		int gap = abs(from - item->line);

		/* Another hit in the same line, no need to expand range */
		if (from == item->line)
		{
			range_found = true;
			break;
		}

		/* Increase range */
		else if (gap < scan->snippet_range_tolerance)
		{
			range_found = true;
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

	if (!range_found)
	{
		matchmap_range *new_range = (matchmap_range *)realloc(scan->matchmap[found].range, sizeof(matchmap_range) * (scan->matchmap[found].ranges_number + 1));
		if (new_range != NULL) {
			scan->matchmap[found].range = new_range;
			/* New range */
			scan->matchmap[found].range[scan->matchmap[found].ranges_number].from = item->line;
			scan->matchmap[found].range[scan->matchmap[found].ranges_number].to = item->line;
			scan->matchmap[found].range[scan->matchmap[found].ranges_number].oss_line = oss_line;
			scan->matchmap[found].ranges_number++;
		} 
		else 
		{
			scanlog("Failed to add a new range, not memory available");
		}
	}

	/* Update last wfp */
	if (lastwfp)
		memcpy(lastwfp, item->wfp, WFP_LN);

	if (found == scan->matchmap_size)
		scan->matchmap_size++;
	return 0;
}

/**
 * @brief Main function of snippet scanning. Produce the matchmap processing the incoming wfps
 * @param scan current scan structure
 * @return match_t returns the type of scan result.
 */
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

	matchmap_setup(scan);
	if (scan->snippet_adjust_tolerance)
		adjust_tolerance(scan);

	/* First build a map with all the MD5s related with each WFP from the source file*/
	matchmap_entry_t map[scan->hash_count];
	/* map_lines_indirection will be used to keep track of the porcessed lines*/
	int8_t map_lines_indirection[scan->lines[scan->hash_count -1] + 1];
	memset(map_lines_indirection, -1, sizeof(map_lines_indirection));
	int lines_coverage = 0;
	int map_max_size = 0;
	/*Fill up the map with the md5s related with each wfp*/
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
		//Initializate the lines indirection when a wfp from a line has at least one md5 linked
		if (map[i].size)
			map_lines_indirection[scan->lines[i]] = 0;

		if (map[i].size > map_max_size)
			map_max_size = map[i].size;
		
	}
	/* Classify the WFPs in cathegories depending on popularity
	Each cathegoy will contain a sub set of index refered to map rows*/
	#define MAP_INDIRECTION_CAT_NUMBER 1000
	#define MAP_INDIRECTION_CAT_SIZE (map_max_size / MAP_INDIRECTION_CAT_NUMBER) == 0 ? 1 : (map_max_size / MAP_INDIRECTION_CAT_NUMBER)
	int map_indedirection_items_size = (scan->hash_count / (MAP_INDIRECTION_CAT_NUMBER))/ 10 < 10 ? 
													scan->hash_count : 
													(scan->hash_count / (MAP_INDIRECTION_CAT_NUMBER))/ 10;

	int * map_indirection[MAP_INDIRECTION_CAT_NUMBER]; //define the cathegories
	int map_indirection_index[MAP_INDIRECTION_CAT_NUMBER]; //index for each cathegory
	
	memset(map_indirection, 0, sizeof(map_indirection));
	memset(map_indirection_index, 0, sizeof(map_indirection_index));

	scanlog ("< Snippet scan setup: Total lines: %d ,Matchmap size: %d, Min hits: %d, Min lines: %d, Map max size = %d, Cat N = %d x %d, Cat size = %d >\n", 
			scan->total_lines, scan->max_matchmap_size, scan->snippet_min_hits, scan->snippet_min_lines, map_max_size, MAP_INDIRECTION_CAT_NUMBER, map_indedirection_items_size, MAP_INDIRECTION_CAT_SIZE);

	for (int i =0; i < scan->hash_count; i++)
	{
		if ( map[i].size < 1)
			continue;
		int cat = map[i].size / (MAP_INDIRECTION_CAT_SIZE+1);
		if (cat < 0)
			cat = 0;
		//Add one new item to the current cathergory
		int * cat_aux = (int *) realloc(map_indirection[cat], (map_indirection_index[cat] +1) * sizeof(int));
		if (cat_aux)
		{
			map_indirection[cat] = cat_aux;
			map_indirection[cat][map_indirection_index[cat]] = i;
			map_indirection_index[cat]++;
		}
		else
		{
			scanlog("Not available memory to keep adding items to this cathegory %d\n", i);
		}

	}

	if (map_max_size <= 0)
	{
		scanlog("Warning no WFP with hits, returning failed\n");
		return MATCH_NONE;
	}

	/* Calculate a limit to the quantity of cathegories to be processed, 
	the cathegoies with less quantity of MD5s (less popular) will be prioritased*/
	int cat_limit = 0;
	int cat_limit_index=0;
	int hashes_to_process = 0;
	for (int i = 0; i < MAP_INDIRECTION_CAT_NUMBER; i++)
	{
		bool exit = false;
		for (int j=0; j < map_indirection_index[i]; j++)
		{
			if (map[map_indirection[i][j]].size <= 0)
				continue;
			hashes_to_process++;	
			cat_limit += map[map_indirection[i][j]].size;
			if (map_lines_indirection[map[map_indirection[i][j]].line] == 0)
			{
				map_lines_indirection[map[map_indirection[i][j]].line] = 1;
				lines_coverage++; 
			}
			if (cat_limit > scan->max_matchmap_size)
			{
				if ((hashes_to_process < scan->hash_count / 10 || (float) lines_coverage / scan->hash_count < MIN_LINES_COVERAGE) && cat_limit < MAX_MATCHMAP_FILES)
				{
					scan->max_matchmap_size += map[map_indirection[i][j]].size;
				}
				else
				{
					cat_limit_index = i;
					exit = true;
					break;
				}
			}
		}
		if (exit)
			break;
		else
			cat_limit_index = i;
	}

	if (debug_on)
	{
		scanlog("Cathegories result:\n");
		for (int i = 0; i < MAP_INDIRECTION_CAT_NUMBER; i++)
		{
			for (int j=0; j < map_indirection_index[i]; j++)
			{
				uint8_t * wfp = map[map_indirection[i][j]].wfp;
				scanlog("Cat: %d.%d - line %d - %02x%02x%02x%02x - size %d\n",i,j, 
						map[map_indirection[i][j]].line, wfp[0], wfp[1],wfp[2],wfp[3], map[map_indirection[i][j]].size);
			}
		}

		for (int i = 0; i <= scan->lines[scan->hash_count - 1]; i++)
		{
			if (map_lines_indirection[i] > -1 && map_lines_indirection[i] == 0)
			{
				scanlog("Warning ignored line %d\n", i);
			}
		}
	}
	scan->max_matchmap_size = cat_limit;
	scanlog("Map limit on %d MD5s at  %d of %d caths. Selected hashes: %d/%d - lines coverage %d\n",
			scan->max_matchmap_size, cat_limit_index, MAP_INDIRECTION_CAT_NUMBER, hashes_to_process, scan->hash_count, (lines_coverage * 100) / scan->total_lines);
	scan->matchmap = calloc(scan->max_matchmap_size, sizeof(matchmap_entry));

	int map_indexes[scan->hash_count];
	memset(map_indexes, 0, sizeof(map_indexes));

	/*Add MD5s to the matchmap, sorting by sector. First add the MD5s starting with 00, then with 01 and so on*/
	int last_sector_aux = 0;
	for (int  sector = 0; sector < 256; sector++)
	{
		scan->matchmap_rank_by_sector[sector] = -1;
		int sector_max = scan->snippet_min_hits;
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
	for (int sector = 0; sector < 256; sector++)
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
		for (int sector = 0; sector < 256; sector++)
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
		int md5_proceced = 0;
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
					int sector_max = scan->snippet_min_hits;

					if (scan->matchmap_rank_by_sector[sector] < 0)
						continue;
					else
						sector_max = scan->matchmap[scan->matchmap_rank_by_sector[sector]].hits;

					if (md5cmp(&md5s[wfp_p], scan->matchmap[scan->matchmap_rank_by_sector[sector]].md5))
					{				 
						add_file_to_matchmap(scan, &map[i], &md5s[wfp_p], 0, &sector_max, &scan->matchmap_rank_by_sector[sector]);
						md5_proceced++;
					}
				}
			}
			//limit the quantity of iterations to prevent performance issues.
			if (md5_proceced > DEFAULT_MATCHMAP_FILES)
				break;
		}
	}

	//for debuging
	if (debug_on)
	{
		scanlog("Max hits by sector\n");
		for (int sector = 0; sector < 256; sector++)
		{
			if (scan->matchmap_rank_by_sector[sector] >= 0)
				scanlog("Sector %02x, Max at %d with %d\n", sector, scan->matchmap_rank_by_sector[sector], scan->matchmap[scan->matchmap_rank_by_sector[sector]].hits);
		}
	}

	//Free memory
	for (int i = 0; i < scan->hash_count; i++)
	{
		free(map[i].md5_set);
	}

	
	for (int i = 0; i < MAP_INDIRECTION_CAT_NUMBER; i++)
	{
		free(map_indirection[i]);
	}

	if (scan->matchmap_size)
	 	return MATCH_SNIPPET;
	
	scanlog("Snippet scan has no matches\n");
	return MATCH_NONE;


}
