// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/match.c
 *
 * Match processing and output
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
  * @file match.c
  * @date 12 Jul 2020 
  * @brief Contains the functions used for fullyfill the matches list during the scanning
  
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/match.c
  */

#include "match.h"
#include "query.h"
#include "report.h"
#include "debug.h"
#include "limits.h"
#include "util.h"
#include "snippets.h"
#include "versions.h"
#include "url.h"
#include "file.h"
#include "rank.h"
#include "decrypt.h"
#include "hpsm.h"


bool first_file = true;										   /** global first file flag */
const char *matchtypes[] = {"none", "url", "file", "snippet"}; /** describe the availables kinds of match */
bool match_extensions = false;								   /** global match extension flag */

char vendor_hint[MAX_FIELD_LN];
char component_hint[MAX_FIELD_LN];

/**
 * @brief This script replaces \ with /
 * @param data input/output buffer
 */
void flip_slashes(char *data)
{
	int len = strlen(data);
	for (int i = 0; i < len; i++)
		if (data[i] == '\\')
			data[i] = '/';
}

/**
 * @brief Output matches in JSON format via STDOUT
 * @param matches pointer to matches list
 * @param scan_ptr scan_data pointer, common scan information.
 */
void output_matches_json(match_list_t * matches, scan_data *scan_ptr)
{
	scan_data *scan = scan_ptr;

	flip_slashes(scan->file_path);

	/* Log slow query, if needed */
	slow_query_log(scan);

	/* Print comma separator */
	if (!quiet)
		if (!first_file)
			printf(",");
	first_file = false;

	/* Open file structure */
	json_open_file(scan->file_path);

	/* Print matches */
	if (matches->headp.lh_first)
	{
		match_list_print(matches, print_json_match, ",");
	}
	else
		print_json_nomatch(scan);
	
	json_close_file();
}

/**
 * @brief Return true if asset is found in ignore_components (-b parameter) 
 * @param url_record pointer to url record
 */
bool ignored_asset_match(uint8_t *url_record)
{
	if (!ignore_components)
		return false;

	/* Extract fields from URL record */
	char *vendor = calloc(LDB_MAX_REC_LN, 1);
	char *component = calloc(LDB_MAX_REC_LN, 1);
	char *purl = calloc(LDB_MAX_REC_LN, 1);

	extract_csv(vendor, (char *)url_record, 1, LDB_MAX_REC_LN);
	extract_csv(component, (char *)url_record, 2, LDB_MAX_REC_LN);
	extract_csv(purl, (char *)url_record, 6, LDB_MAX_REC_LN);

	bool found = false;

	/* Travel ignore_components */
	for (int i = 0; i < MAX_SBOM_ITEMS; i++)
	{
		char *dvendor = ignore_components[i].vendor;
		char *dcomponent = ignore_components[i].component;
		char *dpurl = ignore_components[i].purl;

		/* Exit if reached the end */
		if (!*dcomponent && !*dvendor && !*dpurl)
			break;

		/* Compare purl */
		if (*dpurl)
		{
			if (!strcmp((const char *)purl, (const char *)dpurl))
			{
				found = true;
				break;
			}
		}

		/* Compare vendor and component */
		else
		{
			bool vendor_match = !*dvendor || !strcmp(vendor, dvendor);
			bool component_match = !*dcomponent || !strcmp(component, dcomponent);
			if (vendor_match && component_match)
			{
				found = true;
				break;
			}
		}
	}

	free(vendor);
	free(component);
	free(purl);

	if (found)
		scanlog("Component ignored: %s\n", url_record);
	return found;
}

/**
 * @brief Fill the match structure
 * @param url_key md5 of the match url
 * @param file_path file path
 * @param url_record pointer to url record
 * @return match_data fullfilled structure
 */
bool fill_component(component_data_t * component, uint8_t *url_key, char *file_path, uint8_t *url_record)
{
	char vendor[MAX_FIELD_LN];
	char component[MAX_FIELD_LN];
	char version[MAX_FIELD_LN];
	char release_date[MAX_FIELD_LN];
	char latest_release_date[MAX_FIELD_LN];
	char latest_version[MAX_FIELD_LN];
	char main_url[MAX_FILE_PATH];
	char license[MAX_FIELD_LN];
	char url[MAX_FILE_PATH];
	char purl[MAX_FILE_PATH];
	uint8_t purl_md5[MD5_LEN];
	component->path_ln = 0;
	
	/* Extract fields from file record */
	if (url_key)
	{
		memcpy(component->url_md5, url_key, MD5_LEN);
		component->file = strdup(file_path);
		component->path_ln = strlen(file_path);
		flip_slashes(component->file);
	}

	/* Extract fields from url record */
	extract_csv(vendor, (char *)url_record, 1, sizeof(vendor));
	extract_csv(component, (char *)url_record, 2, sizeof(component));
	extract_csv(version, (char *)url_record, 3, sizeof(version));
	extract_csv(release_date, (char *)url_record, 4, sizeof(release_date));
	extract_csv(license, (char *)url_record, 5, sizeof(license));
	extract_csv(purl, (char *)url_record, 6, sizeof(purl));
	extract_csv(url, (char *)url_record, 7, sizeof(url));
	strcpy(latest_version, version);

	flip_slashes(vendor);
	flip_slashes(component);
	flip_slashes(version);
	flip_slashes(url);

	if (!*url || !*version || !*purl)
	{
		scanlog("Incomplete metadata for %s\n", file_path);
		return false;
	}
	component->vendor = strdup(vendor);
	component->component = strdup(component);
	component->version = strdup(version);
	component->release_date = strdup(release_date);
	component->license = strdup(license);
	component->purls[0] = strdup(purl);
	component->url = strdup(url);
	component->latest_version = strdup(latest_version);
	if (*purl)
	{
		component->purls_md5[0] = malloc(MD5_LEN);
		MD5((uint8_t *)purl, strlen(purl), component->purls_md5[0]);
		component->age = get_component_age(component->purls_md5[0]);
	}
	return true;
}

/**
 * @brief Count matches into a matches list
 * @param matches matches list
 * @return count of matches
 */
int count_matches(match_data *matches)
{
	if (!matches)
	{
		scanlog("Match metadata is empty\n");
		return 0;
	}
	int c = 0;
	for (int i = 0; i < scan_limit && matches[i].loaded; i++)
		c++;
	return c;
}

/**
 * @brief Adds match to matches list
 * @param position position to add the new match
 * @param match new match
 * @param matches matches list
 */
void add_match(int position, match_data match, match_data *matches)
{

	/* Verify if metadata is complete */
	if (!*match.url || !*match.version || !*match.file || !*match.purl[0] || strlen(match.release_date) < 4)
	{
		scanlog("Metadata is incomplete: %s,%s,%s,%s,%s\n", match.purl[0], match.version, match.url, match.file, match.release_date);
		return;
	}
	int n = count_matches(matches);

	if (n >= scan_limit)
	{
		scanlog("Match list is full\n");
		return;
	}

	/* Attempt to place match among existing ones */
	bool placed = false;

	for (int i = 0; i < n; i++)
	{
		/* Are purls the same? */
		if (!strcmp(matches[i].purl[0], match.purl[0]))
		{
			placed = true;
			/* Compare version and, if needed, update range (version-latest) */
			if (strcmp(match.version, matches[i].version) < 0)
			{
				strcpy(matches[i].version, match.version);
			}
			if (strcmp(match.version, matches[i].latest_version) > 0)
			{
				strcpy(matches[i].latest_version, match.version);
			}
		}
	}

	/* Otherwise add a new match */
	if (!placed)
	{
		/* Match position is given */
		if (!(engine_flags & DISABLE_BEST_MATCH))
		{
		/* Locate free position */
			n = 0;
			if (matches[n].loaded && strcmp(matches[n].release_date, match.release_date) < 0)
				return;
			while (matches[n].loaded && strcmp(matches[n].release_date, match.release_date) == 0 && n < scan_limit)
				n++;
		}

		if (n > scan_limit)
			return;

		if (!matches[n].loaded || strcmp(matches[n].release_date, match.release_date) >= 0)
		{
			scanlog("New best match: %s - %s\n", matches[n].release_date, match.release_date);
			/* Copy match information */
			strcpy(matches[n].vendor, match.vendor);
			strcpy(matches[n].component, match.component);
			strcpy(matches[n].purl[0], match.purl[0]);
			memcpy(matches[n].purl_md5[0], match.purl_md5[0], MD5_LEN);
			strcpy(matches[n].version, match.version);
			strcpy(matches[n].latest_version, match.latest_version);
			strcpy(matches[n].url, match.url);
			strcpy(matches[n].file, match.file);
			strcpy(matches[n].license, match.license);
			strcpy(matches[n].release_date, match.release_date);
			memcpy(matches[n].url_md5, match.url_md5, MD5_LEN);
			memcpy(matches[n].file_md5, match.file_md5, MD5_LEN);
			matches[n].path_ln = match.path_ln;
			matches[n].selected = match.selected;
			matches[n].type = match.type;
			matches[n].loaded = true;
		}
	}
}


/**
 * @brief Sort len_rank
 * @param a len_rank a
 * @param b len_rank b
 * @return 1 if a is longer than b, -1 if b is longer than a
 */
static int path_struct_cmp(const void *a, const void *b) {
    const len_rank *v1 = (const len_rank *) a;
    const len_rank *v2 = (const len_rank *) b;
    if (v1->len > v2->len) return 1;
    if (v1->len < v2->len) return -1;
	return 0;
}

static bool load_components(component_list_t * component_list, file_recordset *files, int records)
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
	
	for (int r = 0; r < SHORTEST_PATHS_QTY; r++)
	{
		if (!path_rank[r].len || !*files[path_rank[r].id].path)
			continue;

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

		component_data_t * new_comp = malloc(new_comp);
		bool result = fill_component(new_comp, NULL, NULL, (uint8_t*) url_rec);
		if (result)
		{
			int n = path_rank[r].id;
			memcpy(new_comp->url_md5, files[n].url_id, MD5_LEN);
			release_version  release = {.version = "0", .date = "0"};
			if (!files[n].url_id].external) 
				get_purl_version(release, new_comp->purls[0], files[n].url_id);
/*
			if (*release.version) 
				update_version_range(matches, release);
*/			
			component_list_add(component_list, new_comp, NULL, true);
		}
		else
			component_data_free(new_comp);
	}
	free(url_rec);
	free(old_rec);
	free(path_rank);
	return true;
}


/**
 * @brief load matches into the scan
 * @param scan scan data
 * @param matches matches list
 */
void load_matches (scan_data * scan, match_data_t *match)
{
	
	if (match->type == MATCH_FILE)
	{
		asprintf(&match->line_ranges, "all");
		asprintf(&match->oss_ranges, "all");
		asprintf(&match->matched_percent, "100%%");
	}

	/* Compile match ranges and fill up matched percent */
	int hits = 100;
	int matched_percent = 100;

	/* Get matching line ranges (snippet match) */
	if (match->type == snippet)
	{
		hits = compile_ranges(match);

		float percent = (hits * 100) / scan->total_lines;
		if (hits)
			matched_percent = floor(percent);
		if (matched_percent > 99)
			matched_percent = 99;
		if (matched_percent < 1)
			matched_percent = 1;

		scanlog("compile_ranges returns %d hits\n", hits);
		if (!hits)
			return;

		asprintf(&match->matched_percent, "%u%%", matched_percent);
	}

	uint32_t records = 0;

	/* Snippet and url match should look for the matching md5 in urls */
	if (scan->match_type != file)
	{
		records = ldb_fetch_recordset(NULL, oss_url, scan->match_ptr, false, handle_url_record, (void *)&match->component_list);
		scanlog("URL recordset contains %u records\n", records);
	}

	file_recordset *files = calloc(2 * FETCH_MAX_FILES, sizeof(file_recordset));
	records = ldb_fetch_recordset(NULL, oss_file, scan->match_ptr, false, collect_all_files, (void *)files);
	if (records)
	{
		load_components(&match->component_list, files, records);
	}

	/* Add version ranges to selected match */
	//add_versions(matches, files, records); moved to load componnets
	//update_version_range(matches, release); add here
	free(files);

	if (!records)
		scanlog("Match type is 'none' after loading matches\n");
}

scan_data * scan_aux;
bool match_process(match_data_t * fp1)
{
	load_matches(scan_aux, fp1);
}
/**
 * @brief Compile matches if DISABLE_BEST_MATCH is one
 * @param scan scan data
 * @return matches list
 */
match_list_t * compile_matches(scan_data *scan)
{
	scan->match_ptr = scan->md5;
	match_list_t * list = NULL;
	scan_aux = scan;
	/* Search for biggest snippet */
	if (scan->match_type == snippet)
	{
		/* Dump match map */
		if (debug_on)
			map_dump(scan);

		scanlog("%ld matches in snippet map\n", scan->matchmap_size);
		list = biggest_snippet(scan);
	}
	else
	{
		struct match_data matches[3];
		memset(matches, 0, sizeof(matches));
		list = match_list_init();
		match_data_t * match_new = malloc(sizeof(match_data_t));
		match_new->type = MATCH_FILE;
		match_list_add(list, match_new, NULL, false);
	}
	
		// /* No match pointer */
		// if (!scan->match_ptr)
		// {
		// 	/* No previous matches loaded, exit */
		// 	if (!matches[0].loaded)
		// 	{
		// 		scan->match_type = none;
		// 		scanlog("No matching file id\n");
		// 		return NULL;
		// 	}
		// }

		/* Gather and load match metadata */
		scanlog("Starting match: %s\n", matchtypes[scan->match_type]);
		if (scan->match_type != none)
		{
			match_list_process(list, match_process);
		}

		/* Loop only if DISABLE_BEST_MATCH and match type is snippet */
//	} while ((engine_flags & DISABLE_BEST_MATCH) && scan->match_type == snippet);

	//for (int i = 0; i < scan_limit && *matches[i].component; i++)
	//	scanlog("Match #%d = %d - %s\n", i, matches[i].selected, matches[i].release_date);

	/* The latter could result in no matches */
	//if (!matches[0].loaded)
	//	scan->match_type = none;
	//scanlog("Final match: %s\n", matchtypes[scan->match_type]);
	return list;
}
