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
 * @brief Add component to component_rank
 * @param component_rank component rank structure
 * @param vendor component vendor
 * @param component component name
 * @param purl component purl
 * @param purl_md5 md5 hash of the component purl
 * @param path component path
 * @param url_id md5 of the url
 * @param url_record url record
 */
void update_component_rank(\
component_name_rank *component_rank,
char *vendor,
char *component,
char *purl,
uint8_t *purl_md5,
char *path,
uint8_t *url_id,
char *url_record)
{
	/* Walk ranking items */
	for (int i = 0; i < rank_items; i++)
	{
		if (!component_rank[i].score)
		{
			strcpy(component_rank[i].vendor, vendor);
			strcpy(component_rank[i].component, component);
			strcpy(component_rank[i].file, path);
			strcpy(component_rank[i].url_record, url_record);
			strcpy(component_rank[i].purl, purl);

			if (purl_md5) memcpy(component_rank[i].purl_md5, purl_md5, MD5_LEN);
			else memset(component_rank[i].purl_md5, 0, MD5_LEN);

			if (url_id) memcpy(component_rank[i].url_id, url_id, MD5_LEN);
			else memset(component_rank[i].url_id, 0, MD5_LEN);

			component_rank[i].score++;
			component_rank[i].age = get_component_age(purl_md5);
			return;
		}
		bool vendor_ok = false;
		if (*vendor)
		{
			if (stristart(component_rank[i].vendor, vendor)) vendor_ok = true;
		}
		else vendor_ok = true;
		if (vendor_ok && stristart(component_rank[i].component, component))
		{
			component_rank[i].score++;
			return;
		}
	}
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
 * @brief Look for hints of /external/ component names in collected file paths
 * @param files pointer to file recordset list
 * @param records number of records
 * @param hint listo of hints to find
 * @param component_rank component name rank list
 */
void external_component_hint_in_path(file_recordset *files, int records, char *hint, component_name_rank *component_rank)
{
	bool found = false;

	/* Walk through file records */
	for (int i = 0; i < records; i++)
	{
		/* Attempt to get a component name */
		get_external_component_name_from_path(files[i].path, hint);
		if (*hint)
		{
			/* Add component to rank */
			update_component_rank(component_rank, "", hint, "", NULL, "", NULL, "");
			files[i].external = true;
			found = true;
		}
	}

	if (found) select_best_component_from_rank(component_rank, hint);
	log_component_ranking(component_rank);
	scanlog("external_component_hint_in_path returned: %s\n", found ? hint : "no hints");
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
 * @brief Select the path matcihin with 
 * @param files pointer to file recordset list
 * @param records number of records
 * @param path_rank[out] pointer to path rank list
 * @param hint1 hint 1
 * @param hint2 hint 2
 * @return true if there is a match
 */
bool select_paths_matching_component_names_in_rank(\
		file_recordset *files,\
		int records,\
		component_name_rank *component_rank,\
		path_ranking *path_rank,\
		char *hint1,\
		char *hint2)
{
	bool found = false;

	uint8_t *url_rec = calloc(LDB_MAX_REC_LN, 1);

	if (*hint1 || *hint2) scanlog("Hints %s, %s\n", hint1, hint2);

	/* Walk through the ranking */
	for (int i = 0; i < rank_items; i++)
	{
		if (path_rank[i].score)
		{
			bool skip = true;

			/* If there are component hints, accept only matching files */
			if (!files[path_rank[i].pathid].external)
			{

				/* If hints are provided, consider only paths starting with either hint */
				if (*hint1 || *hint2)
				{
					if ((stristart(files[path_rank[i].pathid].path, hint1) || \
								stristart(files[path_rank[i].pathid].path, hint2)))
					{
						skip = false;
					}
				}

				/* If no hints are provided, path is considered */
				else skip = false;
			}

			if (!skip)
			{
				*path_rank[i].component = 0;
				*path_rank[i].vendor = 0;
				*path_rank[i].purl = 0;

				/* Fetch vendor, component name and purl */
				get_url_record(files[path_rank[i].pathid].url_id, url_rec);
				extract_csv(path_rank[i].vendor, (char *) url_rec, 1, sizeof(path_rank[0].vendor));
				extract_csv(path_rank[i].component, (char *) url_rec, 2, sizeof(path_rank[0].component));
				extract_csv(path_rank[i].purl, (char *) url_rec, 6, sizeof(path_rank[0].purl));
				MD5((uint8_t *)path_rank[i].purl, strlen(path_rank[i].purl), path_rank[i].purl_md5);

				/* If the path starts with the component name, add it to the rank */
				if (stristart(path_rank[i].component, files[path_rank[i].pathid].path))
				{
					update_component_rank(\
							component_rank,\
							path_rank[i].vendor,\
							path_rank[i].component,\
							path_rank[i].purl,\
							path_rank[i].purl_md5,\
							files[path_rank[i].pathid].path,\
							files[path_rank[i].pathid].url_id,\
							(char *) url_rec);
					found = true;
				}
			}
		}
	}

	free(url_rec);

	scanlog("select_paths_matching_component_names_in_rank returned %shints\n", found?"":"NO ");
	return found;
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
 * @brief Search for a matching component hint among files with shortest paths
 * 
 * @param files 
 * @param records 
 * @param hint1 
 * @param hint2 
 * @param component_rank 
 * @param path_rank 
 * @return true 
 * @return false 
 */
bool component_hint_from_shortest_paths(\
		file_recordset *files,\
		int records,\
		char *hint1,\
		char *hint2,\
		component_name_rank *component_rank,\
		path_ranking *path_rank)
{
	/* Init component ranking */
	init_component_ranking(component_rank);

	bool hint_found = false;

	/* Collect shortest paths */
	collect_shortest_paths(files, records, path_rank);

	/* Query components for those shortest paths, and select those
		 which match with component name */
	hint_found = select_paths_matching_component_names_in_rank(files, records,\
			component_rank, path_rank, hint1, hint2);

	/* Add component age */
	fill_component_age(component_rank);

	scanlog("search_component_hint returned %shints\n", hint_found ? "" : "NO ");

	return hint_found;
}

/**
 * @brief Add relevant files into matches structure
 * @param files pointer to file recordset list to be added
 * @param records number of records
 * @param component_hint component hint string
 * @param file_md5 file md5 hash
 * @param matches pointer to matches list
 * @param add_all true for add all files
 * @return number of files added
 */
int add_files_to_matches(\
		file_recordset *files,\
		int records,\
		char *component_hint,\
		uint8_t *file_md5,\
		match_data *matches, bool add_all)
{
	int considered=0;

	/* Walk through all file records and add the relevant ones to *matches */
	for (int i = 0; i < records; i++)
	{
		if (!files[i].external)
		{
			if (add_all || strstr(files[i].path, component_hint))
			{
				consider_file_record(\
						files[i].url_id,\
						files[i].path,\
						matches,\
						component_hint,\
						file_md5);
				considered++;
			}
		}
	}
	scanlog("%u of %u files considered\n", considered, records);
	return considered;
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
uint8_t *select_best_top_date(int dup_dates, uint8_t *top_recs, uint8_t *top_md5s)
{
	if (!dup_dates) return top_recs;

	char release_date[MAX_ARGLN + 1] = "\0";
	char oldest[MAX_ARGLN + 1] = "9999";
	uint8_t *oldest_ptr = top_recs;

	/* Walk dup_dates and save pointer to top_recs with oldest first release date */
	for (int i = 0; i <= dup_dates; i++)
	{

		uint8_t *rec = top_recs + (i * LDB_MAX_REC_LN);
		uint8_t *md5 = top_md5s + (i * MD5_LEN);
		if (!*rec) continue;

		purl_release_date(rec, release_date);
		if (*release_date) if (strcmp(release_date, oldest) < 1)
		{
			oldest_ptr = rec;
			strcpy(oldest, release_date);
			memcpy(top_md5s, md5, MD5_LEN);
		}
	}

	return oldest_ptr;
}

/**
 * @brief Look for shortest file paths and query component/purl information to determine
	 the most interesting match
 * @param files pointer to files recordset list
 * @param records records numbers
 * @param component_rank pointer to component rank list
 * @return index of the selected item
 */
int shortest_paths_check(file_recordset *files, int records, component_name_rank *component_rank)
{
	/* Wipe component_rank */
	clear_component_rank(component_rank);
	int selected = -1;

	/* Load path rank */
	len_rank *path_rank = load_path_rank(files, records);

	/* Sort path_rank array from shortest to largest path */
	qsort(path_rank, SHORTEST_PATHS_QTY, sizeof(len_rank), path_struct_cmp);

	/* Dump rank contents into log */
	dump_path_rank(path_rank, files);

	/* Obtain oldest URL record */
	const int TOP_BEST_DATES = 100;
	uint8_t *url_rec = calloc(LDB_MAX_REC_LN, 1);
	uint8_t *old_rec = calloc(LDB_MAX_REC_LN, 1);
	uint8_t *top_recs = calloc(LDB_MAX_REC_LN * TOP_BEST_DATES, 1);
	uint8_t *top_md5s = calloc(LDB_MAX_REC_LN * MD5_LEN, 1);
	int path_id = 0;
	int dup_dates = 0;
	char date[MAX_ARGLN + 1] = "\0";
	char oldest[MAX_ARGLN + 1] = "9999";

	for (int r = 0; r < SHORTEST_PATHS_QTY; r++)
	{
		if (path_rank[r].len)
		{
			strcpy((char *) url_rec, "9999");
			ldb_fetch_recordset(NULL, oss_url, files[path_rank[r].id].url_id, false, get_oldest_url, (void *) url_rec);

			/* Extract date from url_rec */
			*date = 0;
			extract_csv(date, (char *) url_rec , 4, MAX_ARGLN);
			if (!*date) continue;

			if (strcmp((char *) date, (char *) oldest) < 0)
			{
				dup_dates = 0;
				path_id = path_rank[r].id;
				strcpy((char *) old_rec, (char *) url_rec);
				strcpy((char *) top_recs, (char *) url_rec);
				memcpy(top_md5s, files[path_rank[r].id].url_id, MD5_LEN);
				strcpy(oldest, date);
			}

			else if (!strcmp(date, oldest))
			{
				if (++dup_dates >= TOP_BEST_DATES) dup_dates = TOP_BEST_DATES - 1;
				strcpy((char *) top_recs + LDB_MAX_REC_LN * dup_dates, (char *) url_rec);
				memcpy(top_md5s + MD5_LEN * dup_dates, files[path_rank[r].id].url_id, MD5_LEN);
			}
		}
	}

	char release_date[MAX_ARGLN + 1] = "\0";
	extract_csv(release_date, (char *) top_recs, 4, MAX_ARGLN);

	if (*release_date)
	{
		uint8_t *best_rec = select_best_top_date(dup_dates, top_recs, top_md5s);
		scanlog("shortest_paths_check() best_rec = %s\n", best_rec);

		/* Fetch vendor and component name */
		char vendor[MAX_ARGLN + 1] = "\0";
		char component[MAX_ARGLN + 1] = "\0";
		char purl[MAX_ARGLN + 1] = "\0";
		extract_csv(vendor, (char *) best_rec, 2, MAX_ARGLN);
		extract_csv(component, (char *) best_rec, 3, MAX_ARGLN);
		extract_csv(purl, (char *) best_rec, 7, MAX_ARGLN);
		uint8_t purl_md5[MD5_LEN];
		MD5((uint8_t *)purl, strlen(purl), purl_md5);

		/* Insert winning record and select first and only item */
		update_component_rank(component_rank, vendor, component, purl, purl_md5, files[path_id].path, top_md5s, (char *) best_rec);
		selected = 0;
	}
	else scanlog("shortest_paths_check() best_rec not selected\n");

	free(url_rec);
	free(old_rec);
	free(top_recs);
	free(top_md5s);
	free(path_rank);
	return selected;
}

/**
 * @brief Analyse files, selecting those matching the provided hints
	 return the file id if matched, otherwise a negative value if no hits
 * @param files pointer to file recordset list
 * @param records records number
 * @param hint hint string
 * @param component_rank pointer to component_name_rank
 * @return file id if matched, -1 otherwise
 */
int seek_component_hint_in_path(\
		file_recordset *files,\
		int records,\
		char *hint,\
		component_name_rank *component_rank)
{
	/* No hits returns a negative value */
	if (!*hint) return -1;

	uint8_t *url_rec = calloc(LDB_MAX_REC_LN, 1);
	bool hits = false;
	clear_component_rank(component_rank);

	/* Walk files, adding to rank those paths which:
		 - Start with the hint
		 - Point to a component name matching the hint */
	for (int i = 0; i < records; i++)
	{
		bool skip = true;

		/* If the path starts the hint, check vendor and component */
		if (stristart(hint, files[i].path)) skip = false;

		if (!skip)
		{
			/* Fetch vendor and component name */
			get_url_record(files[i].url_id, url_rec);
			char vendor[MAX_ARGLN + 1] = "\0";
			char component[MAX_ARGLN + 1] = "\0";
			char purl[MAX_ARGLN + 1] = "\0";
			extract_csv(vendor, (char *) url_rec, 1, MAX_ARGLN);
			extract_csv(component, (char *) url_rec, 2, MAX_ARGLN);
			extract_csv(purl, (char *) url_rec, 2, MAX_ARGLN);
			uint8_t purl_md5[MD5_LEN];
			MD5((uint8_t *)purl, strlen(purl), purl_md5);

			/* If the path starts with the component name, add it to the rank */
			if (stristart(component, files[i].path))
			{
				update_component_rank(component_rank, vendor, component, purl, purl_md5, files[i].path, files[i].url_id, (char *) url_rec);
				hits = true;
			}
		}
	}
	free(url_rec);

	/* Add component age to rank */
	if (hits)
	{
		int selected_id = fill_component_age(component_rank);
		log_component_ranking(component_rank);
		if (selected_id >= 0) return selected_id;
	}

	scanlog("seek_component_hint_in_path for %s results in no hits\n", hint);
	return -1;
}

/**
 * @brief Analyse files, selecting those with a component name matching the beginning of the path
 * @param files pointer to file recorset list
 * @param records records number
 * @param component_rank pinter to component rank list
 * @return index of the selected item
 */
int seek_component_hint_in_path_start(\
		file_recordset *files,\
		int records,\
		component_name_rank *component_rank)
{
	uint8_t *url_rec = calloc(LDB_MAX_REC_LN, 1);
	bool hits = false;
	clear_component_rank(component_rank);

	/* Walk files, adding to rank those starting with its component name */
	for (int i = 0; i < records; i++)
	{
		/* Fetch vendor, component and purl */
		get_url_record(files[i].url_id, url_rec);
		char vendor[MAX_ARGLN + 1] = "\0";
		char component[MAX_ARGLN + 1] = "\0";
		char purl[MAX_ARGLN + 1] = "\0";
		extract_csv(vendor, (char *) url_rec, 1, MAX_ARGLN);
		extract_csv(component, (char *) url_rec, 2, MAX_ARGLN);
		extract_csv(purl, (char *) url_rec, 2, MAX_ARGLN);
		uint8_t purl_md5[MD5_LEN];
		MD5((uint8_t *)purl, strlen(purl), purl_md5);

		/* If the path starts with the component name, add it to the rank */
		if (stristart(component, files[i].path))
		{
			update_component_rank(component_rank, vendor, component, purl, purl_md5, files[i].path, files[i].url_id, (char *) url_rec);
			hits = true;
		}
	}
	free(url_rec);

	int selected = -1;

	/* Select most repeated component */
	if (hits)
	{
		selected = rank_by_occurrences(component_rank);
		log_component_ranking(component_rank);
	}

	if (selected >= 0) scanlog("seek_component_hint_in_path_start selected path #%d\n",selected);
	else scanlog("seek_component_hint_in_path_start results in no hits\n");

	return selected;
}

/**
 * @brief Select match based on hint and age
 * @param matches pointer to matches list
 * @return true is there is a match.
 */
bool select_best_match(match_data *matches)
{
	scanlog("Running select_best_match()\n");
	long oldest = 0;
	int oldest_id = 0;

	/* Search for matches in component with version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		int age = get_component_age(matches[i].purl_md5[0]);
		if (age > oldest)
		{
			oldest = age;
			oldest_id = i;
		}
	}

	/* Mark oldest component as selected match */
	if (oldest)
	{
		matches[oldest_id].selected = true;
		scanlog("Selected match #%d (%s/%s) with age = %ld\n",\
				oldest_id,
				matches[oldest_id].vendor,\
				matches[oldest_id].component,\
				oldest);
		return true;
	}
	else scanlog("Component age returns no matches\n");

	return false;
}
