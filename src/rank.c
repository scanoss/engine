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
#include "stdbool.h"
#include "rank.h"
#include "util.h"
#include "debug.h"
#include "query.h"
#include "blacklist.h"
#include "limits.h"

/* Determine if a path is to be dismissed */
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

/* Determine if a keyword is indication of an external component */
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

/* Add component to component_rank */
void update_component_rank(\
component_name_rank *component_rank,
char *vendor,
char *component,
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
			if (url_id) memcpy(component_rank[i].url_id, url_id, MD5_LEN);
			component_rank[i].score++;
			component_rank[i].age = component_age(vendor, component);
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

/* Attempt to guess a component name from the file path */
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
		if (is_indicator)
		{
			if (strlen(token) < MAX_FIELD_LN)
			{
				strcpy(component, token);
				return;
			}
		}
	}
}

/* Returns the component age for a vendor/component */
long component_age(char *vendor, char *component)
{
	if (!*vendor || !*component) return 0;

	uint8_t pair_md5[16] = "\0";
	vendor_component_md5(vendor, component, pair_md5);
	return get_component_age(pair_md5);
}


/* Write contents of component_rank to log file */
void log_component_ranking(component_name_rank *component_rank)
{
	if (!debug_on) return;

	/* Walk component ranking and print contents */
	for (int i = 0; i < rank_items; i++)
	{
		if (!component_rank[i].score) break;
		scanlog("component_rank #%02d= %s/%s, score = %ld, age = %ld\n",\
				i,\
				component_rank[i].vendor,\
				component_rank[i].component,\
				component_rank[i].score, component_age(component_rank[i].vendor,component_rank[i].component));
	}
}

/* Log path ranking values */
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

/* Look for hints of /external/ component names in collected file paths */
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
			update_component_rank(component_rank, "", hint, "", NULL, "");
			files[i].external = true;
			found = true;
		}
	}

	if (found) select_best_component_from_rank(component_rank, hint);
	log_component_ranking(component_rank);
	scanlog("external_component_hint_in_path returned: %s\n", found ? hint : "no hints");
}

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

/* Collect the the shortest paths into rank */
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
				/* Fetch vendor and component name */
				get_url_record(files[path_rank[i].pathid].url_id, url_rec);
				extract_csv(path_rank[i].vendor, (char *) url_rec, 1, sizeof(path_rank[0].vendor));
				extract_csv(path_rank[i].component, (char *) url_rec, 2, sizeof(path_rank[0].component));

				/* If the path starts with the component name, add it to the rank */
				if (stristart(path_rank[i].component, files[path_rank[i].pathid].path))
				{
					update_component_rank(\
							component_rank,\
							path_rank[i].vendor,\
							path_rank[i].component,\
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

/* Update component score with component age, return file id for the oldest */
int fill_component_age(component_name_rank *component_rank)
{
	long oldest = 0;

	/* Return a negative value of no files are matched */
	int oldest_id = -1;

	/* Get age info for selected components */
	for (int i = 0; i < rank_items; i++)
	{
		component_rank[i].score = component_age(\
				component_rank[i].vendor, component_rank[i].component);

		if (component_rank[i].score > oldest)
		{
			oldest = component_rank[i].score;
			oldest_id = i;
		}
	}

	return oldest_id;
}

/* Return id of the item in rank with the highest score */
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

/* Select the vendor that appears the most in the ranking */
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

/* Erase values in component_rank */
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

/* Select the component with the higher rank and update component_hint */
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

/* Initialize component ranking */
void init_component_ranking(component_name_rank *component_rank)
{
	for (int i = 0; i < rank_items; i++)
	{
		component_rank[i].score = 0;
	}
}

/* Initialize path ranking */
void init_path_ranking(path_ranking *path_rank)
{
	for (int i = 0; i < rank_items; i++)
	{
		path_rank[i].score = 0;
		*path_rank[i].vendor = 0;
		*path_rank[i].component = 0;
	}
}

/* Search for a matching component hint among files with shortest paths */
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

/* Add relevant files into matches structure */
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

/* Analyse files, selecting those matching the provided hints
	return the file id if matched, otherwise a negative value if no hits */
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
			char vendor[64] = "\0";
			char component[64] = "\0";
			extract_csv(vendor, (char *) url_rec, 1, 64);
			extract_csv(component, (char *) url_rec, 2, 64);

			/* If the path starts with the component name, add it to the rank */
			if (stristart(component, files[i].path))
			{
				update_component_rank(component_rank, vendor, component, files[i].path, files[i].url_id, (char *) url_rec);
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

/* Analyse files, selecting those with a component name matching the beginning of the path */
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
		/* Fetch vendor and component name */
		get_url_record(files[i].url_id, url_rec);
		char vendor[64] = "\0";
		char component[64] = "\0";
		extract_csv(vendor, (char *) url_rec, 1, 64);
		extract_csv(component, (char *) url_rec, 2, 64);

		/* If the path starts with the component name, add it to the rank */
		if (stristart(component, files[i].path))
		{
			update_component_rank(component_rank, vendor, component, files[i].path, files[i].url_id, (char *) url_rec);
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

/* Select match based on hint and age */
bool select_best_match(match_data *matches)
{
	if (!*component_hint) return false;
	long oldest = 0;
	int oldest_id = 0;

	/* Search for matches in component with version ranges */
	for (int i = 0; i < scan_limit && *matches[i].component; i++)
	{
		if (stricmp(matches[i].component, component_hint))
		{
			int age = component_age(matches[i].vendor, matches[i].component);
			if (age > oldest)
			{
				oldest = age;
				oldest_id = i;
			}
		}
	}

	/* Mark oldest component as selected match */
	if (oldest)
	{
		matches[oldest_id].selected = true;
		scanlog("Selected match %s/%s with age = %ld\n",\
				matches[oldest_id].vendor,\
				matches[oldest_id].component,\
				oldest);
		return true;
	}

	return false;
}
