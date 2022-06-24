// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/rank.c
 *
 * Match ranking subroutines
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
  * @file rank.c
  * @date 31 Jan 2021
  * @brief Contains the functions used to generate the matches ranking
  
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/rank.c
  */
#include "stdbool.h"
#include "rank.h"
#include "util.h"
#include "debug.h"
#include "query.h"
#include "ignorelist.h"
#include "limits.h"
#include "url.h"
#include "parse.h"

/**
 * @brief Determine if a path is to be dismissed
 * @param path input path
 * @return true if the path was dismissed
 */
bool dismiss_path(char *path)
{
	char *skip_paths[] = {
		"arch/",
		"chroot/",
		"debian/",
		"dist/",
		"dist-chroot",
		"home/",
		"include/",
		"lib/",
		"opt/",
		"root/",
		"staging/",
		"usr/",
		NULL
	};

	int i = 0;
	while (skip_paths[i])
	{
		if (stristart(path, skip_paths[i++])) return true;
	}

	return false;
}

/**
 * @brief Determine if a keyword is indication of an external component
 * @param str input component string
 * @return true if it is and external component
 */
bool is_external_indicator(char *str)
{

	char *indicators[] = {
		"3rdparty",
		"contrib",
		"dependencies",
		"dependency",
		"deps",
		"external",
		"libraries",
		"node_modules",
		"opensource",
		"third",
		"third_party",
		"vendor",
		NULL
	};

	int i = 0;
	while (indicators[i])
	{
		if (stricmp(str, indicators[i])) return true;
		i++;
	}

	return false;
}

/**
 * @brief Attempt to guess a component name from the file path
 * @param file_path file path
 * @param component[out] found component
 */
void get_external_component_name_from_path(char *file_path, char *component)
{
	if (!file_path) return;
	if (!*file_path) return;

	*component = 0;
	char path[MAX_PATH];
	strcpy(path, file_path);

	/* Treat the path as a set of tokens separated by / */
	const char s[] = "/";
	char *token;

	/* Get first token */
	token = strtok(path, s);

	/* Get other tokens */
	while	(token)
	{
		bool is_indicator = is_external_indicator(token);
		token = strtok(NULL, s);
		if (token && is_indicator)
		{
			if (strlen(token) < MAX_FIELD_LN)
			{
				strcpy(component, token);
				return;
			}
		}
	}
}

/**
 * @brief Write contents of component_rank to log file
 * @param component_rank pointer to component rank list
 */
void log_component_ranking(component_name_rank *component_rank)
{
	if (!debug_on) return;

	/* Walk component ranking and print contents */
	for (int i = 0; i < rank_items; i++)
	{
		if (!*component_rank[i].component) break;
		scanlog("component_rank #%02d= %s, score = %ld, age = %ld\n",\
				i,\
				component_rank[i].purl,\
				component_rank[i].score, get_component_age(component_rank[i].purl_md5));
	}
}

/**
 * @brief Log path ranking values
 * @param path_rank pointer to path ranking list
 * @param files pointer to file_recordset list
 */
void log_path_ranking(path_ranking *path_rank, file_recordset *files)
{
	if (!debug_on) return;

	/* Walk path ranking and print collected path */
	for (int i = 0; i < rank_items; i++)
	{
		if (!path_rank[i].score) break;
		scanlog("path_rank #%02d: %d, %s\n", i, path_rank[i].score, files[path_rank[i].pathid].path);
	}
}


/**
 * @brief Check if a path exist in a path rank. 
 * @param path_rank pointer to path rank list
 * @param files pointer to file recordset list
 * @param file_id file id
 * @return return true if exist
 */
bool path_exists_in_path_rank(path_ranking *path_rank, file_recordset *files, int file_id)
{
	/* Make sure the path does not already exist in the rank (duplicated) */
	for (int i = 0; i < rank_items; i++)
	{
		if (path_rank[i].score == files[file_id].path_ln)
		{
			if (!strcmp(files[file_id].path, files[path_rank[i].pathid].path))
			{
				return true;
			}
		}
	}
	return false;
}

/**
 * @brief Collect the the shortest paths into rank
 * @param files pointer to files recordset list
 * @param records number of records
 * @param path_rank[out] path ranking list
 */
void collect_shortest_paths(\
		file_recordset *files,\
		int records, path_ranking *path_rank)
{
	/* Ranking is empty */
	int free = 0;

	/* Walk through file records */
	for (int i = 0; i < records; i++)
	{
		bool add = false;

		/* Dismiss path if it the start is not interesting */
		if (dismiss_path(files[i].path)) continue;

		/* If rank position is empty, add record now */
		if (!path_rank[free].score) add = true;

		/* If rank position contains a longer path, then update with current record */
		else if (path_rank[free].score > files[i].path_ln)
		{
			add = true;

			/* Unless the path is already in the rank */
			if (path_exists_in_path_rank(path_rank, files, i))
			{
				add = false;
			}
		}

		if (add)
		{
			*path_rank[free].vendor = 0;
			*path_rank[free].component = 0;
			*path_rank[free].purl = 0;
			memset(path_rank[free].purl_md5, 0, MD5_LEN);
			path_rank[free].score = files[i].path_ln;
			path_rank[free].pathid = i;

			/* Walk through rank to find next free (empty or longest path) */
			int longest = 0;
			for (int t = 0; t < rank_items; t++)
			{

				/* An empty record will be the next free */
				if (!path_rank[t].score)
				{
					free = t;
					break;
				}

				/* The longest path will mark the next free */
				if (path_rank[t].score > longest)
				{
					longest = path_rank[t].score;
					free = t;
				}
			}
		}
	}

	/* Log path ranking outcome */
	scanlog("Shortest path ranking:\n");
	log_path_ranking(path_rank, files);
}


/**
 * @brief Update component score with component age, return file id for the oldest
 * @param component_rank[out] pointer to component rank list
 * @return id of the matched file
 */
int fill_component_age(component_name_rank *component_rank)
{
	long oldest = 0;

	/* Return a negative value of no files are matched */
	int oldest_id = -1;

	/* Get age info for selected components */
	for (int i = 0; i < rank_items; i++)
	{
		component_rank[i].score = get_component_age(component_rank[i].purl_md5);

		if (component_rank[i].score > oldest)
		{
			oldest = component_rank[i].score;
			oldest_id = i;
		}
	}

	return oldest_id;
}

/**
 * @brief Return id of the item in rank with the highest score
 * @param component_rank pointer to component rank list
 * @return id of the item
 */
int highest_score(component_name_rank *component_rank)
{
	long best = 0;

	/* Return a negative value of no files are matched */
	int best_id = -1;

	/* Select highest score */
	for (int i = 0; i < rank_items; i++)
	{
		if (!*component_rank[i].component) break;
		if (component_rank[i].score + component_rank[i].age > best)
		{
			best = component_rank[i].score + component_rank[i].age;
			best_id = i;
		}
	}

	return best_id;
}

/**
 * @brief Select the vendor that appears the most in the ranking
 * @param component_rank pointer to component rank list
 * @return positon in rank with the high score vendor
 */
int rank_by_occurrences(component_name_rank *component_rank)
{
	/* Increment rank by number of occurences */
	for (int i = 0; i < rank_items; i++)
	{
		for (int ii = 0; ii < rank_items; ii++)
		{
			if (!strcmp(component_rank[i].vendor,component_rank[ii].vendor)) component_rank[i].score++;
		}
	}

	/* Return highest score */
	return highest_score(component_rank);
}

/**
 * @brief Erase values in component_rank
 * @param component_rank pointer to component rank list
 */
void clear_component_rank(component_name_rank *component_rank)
{
	for (int i = 0; i < rank_items; i++)
	{
		component_rank[i].score = 0;
		*component_rank[i].component = 0;
		*component_rank[i].vendor = 0;
		*component_rank[i].url_record = 0;
		*component_rank[i].file = 0;
	}
}

/**
 * @brief Select the component with the higher rank and update component_hint
 * @param component_rank component rank list
 * @param component_hint component hint string
 */
void select_best_component_from_rank(\
		component_name_rank *component_rank,\
		char *component_hint)
{
	int best = 0;
	for (int i = 0; i < rank_items; i++)
	{
		if (component_rank[i].score > best)
		{
			best = component_rank[i].score;
			strcpy(component_hint, component_rank[i].component);
		}
	}
}

/**
 * @brief Initialize component ranking
 * @param component_rank pointer to component rank list
 */
void init_component_ranking(component_name_rank *component_rank)
{
	for (int i = 0; i < rank_items; i++)
	{
		component_rank[i].score = 0;
	}
}


/**
 * @brief Reverse sort len_rank
 * @param a len_rank a
 * @param b /len_rank b
 * @return -1 if a is longer than b, 1 if b is longer than a
 */
int path_struct_rcmp(const void *a, const void *b) {
    const len_rank *v1 = (const len_rank *) a;
    const len_rank *v2 = (const len_rank *) b;
    if (v1->len > v2->len) return -1;
    if (v1->len < v2->len) return 1;
	return 0;
}

/**
 * @brief Sort len_rank
 * @param a len_rank a
 * @param b len_rank b
 * @return 1 if a is longer than b, -1 if b is longer than a
 */
int path_struct_cmp(const void *a, const void *b) {
    const len_rank *v1 = (const len_rank *) a;
    const len_rank *v2 = (const len_rank *) b;
    if (v1->len > v2->len) return 1;
    if (v1->len < v2->len) return -1;
	return 0;
}

/**
 * @brief Load path rank and return pointer
 * @param files pointer to file recordset list
 * @param records records number
 * @return pointer to len_rank structure
 */
len_rank *load_path_rank(file_recordset *files, int records)
{
	/* Define path length rank structure */
	len_rank *rank = calloc(sizeof(len_rank), SHORTEST_PATHS_QTY);

	/* Walk files, adding the shortest paths to the rank */
	for (int i = 0; i < records; i++)
	{
		for (int r = 0; r < SHORTEST_PATHS_QTY; r++)
		{
			if (!rank[r].len || (rank[r].len > files[i].path_ln))
			{
				rank[r].len = files[i].path_ln;
				rank[r].id = i;

				/* Reverse sort array */
				qsort(rank, SHORTEST_PATHS_QTY, sizeof(len_rank), path_struct_rcmp);
				break;
			}
		}
	}
	return rank;
}

/**
 * @brief Dump rank contents into log
 * @param path_rank pointer to path rank list
 * @param files pinter to file recordset list
 */
void dump_path_rank(len_rank *path_rank, file_recordset *files)
{
	scanlog(">> Shortest Path Rank BEGINS\n");
	for (int r = 0; r < SHORTEST_PATHS_QTY; r++)
	{
		if (path_rank[r].len)
			scanlog("#%03d %d dirs: %s\n", r, path_rank[r].len, files[path_rank[r].id].path);
	}
	scanlog(">> Shortest Path Rank ENDS\n");
}

/**
 * @brief Select the best record based on oldest date of first release
	querying the pURL table
 * @param dup_dates dup_dates in seconds
 * @param top_recs top records list
 * @param top_md5s top records md5
 * @return pointer to the oldest record
 */

/**
 * @brief Look for shortest file paths and query component/purl information to determine
	 the most interesting match
 * @param files pointer to files recordset list
 * @param records records numbers
 * @param component_rank pointer to component rank list
 * @return index of the selected item
 */
component_name_rank shortest_paths_check(file_recordset *files, int records)
{

	/* Load path rank */
	len_rank *path_rank = load_path_rank(files, records);

	/* Sort path_rank array from shortest to largest path */
	qsort(path_rank, SHORTEST_PATHS_QTY, sizeof(len_rank), path_struct_cmp);

	/* Dump rank contents into log */
	dump_path_rank(path_rank, files);

	/* Obtain oldest URL record */
	uint8_t *url_rec = calloc(LDB_MAX_REC_LN, 1);
	uint8_t *old_rec = calloc(LDB_MAX_REC_LN, 1);

	int path_id = 0;
	char date[MAX_ARGLN + 1] = "\0";
	char purl_date[MAX_ARGLN + 1] = "\0";
	char oldest[MAX_ARGLN + 1] = "9999";
	int min = 999;
	component_name_rank component_rank;
	
	for (int r = 0; r < SHORTEST_PATHS_QTY; r++)
	{
		if (path_rank[r].len && *files[path_rank[r].id].path)
		{
			scanlog("PATH: %s\n", files[path_rank[r].id].path);
			if (path_rank[r].len > 1 && path_rank[r].len < min)
				min = path_rank[r].len;
			
			if (path_rank[r].len > min +1)
				break;
			strcpy((char *) url_rec, "9999");
			ldb_fetch_recordset(NULL, oss_url, files[path_rank[r].id].url_id, false, get_oldest_url, (void *) url_rec);

			/* Extract date from url_rec */
			*date = 0;
			extract_csv(date, (char *) url_rec , 4, MAX_ARGLN);

			if (!*date) continue;

			if (strcmp((char *) date, (char *) oldest) < 0)
			{
				path_id = path_rank[r].id;
				strcpy((char *) old_rec, (char *) url_rec);
				strcpy(oldest, date);
				scanlog("<<<New best: %d,%d,%d - %s - %s>>>\n", r,min, path_rank[r].len, files[path_rank[r].id].path, oldest);
			}

			else if (!strcmp(date, oldest))
			{
				char purl[MAX_ARGLN + 1] = "\0";
				extract_csv(purl, (char *) old_rec , 6, MAX_ARGLN);
				purl_release_date(purl, purl_date); //date of actual purl

				char new_purl[MAX_ARGLN + 1] = "\0";
				extract_csv(new_purl, (char *) url_rec , 6, MAX_ARGLN);
				
				char new_purl_date[MAX_ARGLN + 1] = "\0";
				purl_release_date(new_purl, new_purl_date); //date of new purl
				scanlog("<<<Duplicated: %d,%d,%d - %s - %s - %s/%s>>>\n", r,min, path_rank[r].len, files[path_rank[r].id].path, oldest, purl_date, new_purl_date);

				if (!*new_purl_date)
					continue;

				if (!*purl_date || strcmp(new_purl_date, purl_date) < 1)
				{
					path_id = path_rank[r].id;
					strcpy((char *) old_rec, (char *) url_rec);
				}
			}
		}
	}

	if (*oldest)
	{
		uint8_t *best_rec = old_rec;
		scanlog("shortest_paths_check() best_rec = %s\n", best_rec);

		/* Fetch vendor and component name */
		extract_csv(component_rank.vendor, (char *) best_rec, 2, MAX_ARGLN);
		extract_csv(component_rank.component, (char *) best_rec, 3, MAX_ARGLN);
		extract_csv(component_rank.purl, (char *) best_rec, 7, MAX_ARGLN);
		MD5((uint8_t *)component_rank.purl, strlen(component_rank.purl), component_rank.purl_md5);
		strcpy(component_rank.file, files[path_id].path);
		strcpy(component_rank.url_record, (char*) best_rec);
		memcpy(component_rank.url_id, files[path_id].url_id, MD5_LEN);
		component_rank.age = get_component_age(component_rank.purl_md5);
			/* Insert winning record and select first and only item */
	}
	else scanlog("shortest_paths_check() best_rec not selected\n");

	free(url_rec);
	free(old_rec);
	free(path_rank);
	return component_rank;
}

/**
 * @brief Select match based on hint and age
 * @param matches pointer to matches list
 * @return true is there is a match.
 */
// bool select_best_match(match_data *matches)
// {
// 	scanlog("Running select_best_match()\n");
// 	unsigned long oldest = 0;
// 	int oldest_id = 0;

// 	/* Search for matches in component with version ranges */
// 	for (int i = 0; i < scan_limit && *matches[i].component; i++)
// 	{
// 		unsigned long age = get_component_age(matches[i].purl_md5[0]);
	
// 		if (age > oldest)
// 		{
// 			oldest = age;
// 			oldest_id = i;
// 			scanlog("<<<oldst in  %d - %ld>>>>\n", oldest_id, oldest);

// 		}
// 	}

// 	/* Mark oldest component as selected match */
// 	if (oldest)
// 	{
// 		matches[oldest_id].selected = true;
// 		scanlog("Selected match #%d (%s/%s) with age = %ld\n",\
// 				oldest_id,
// 				matches[oldest_id].vendor,\
// 				matches[oldest_id].component,\
// 				oldest);
// 		return true;
// 	}
// 	else scanlog("Component age returns no matches\n");

// 	return false;
// }
