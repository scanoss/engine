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