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
 * @brief Add all files in recordset to matches
 * @param files recorset pointer
 * @param file_count number of files in the recordset
 * @param scan scan common information
 * @param matches matches list
 * @return added files count
 */
int add_all_files_to_matches(file_recordset *files, int file_count, scan_data *scan, match_data *matches)
{
	scanlog("Adding %d file records to matches\n", file_count);

	for (int i = 0; i < file_count && i < scan_limit; i++)
	{
		/* Create empty match item */
		struct match_data match;// = match_init();

		/* Get URL record */
		uint8_t *url_rec = calloc(LDB_MAX_REC_LN, 1);
		get_url_record(files[i].url_id, url_rec);

		/* Fill match with component info */
		match = fill_match(files[i].url_id, files[i].path, url_rec);
		match.type = url;
		free(url_rec);

		/* Add file MD5 */
		memcpy(match.file_md5, scan->match_ptr, MD5_LEN);
		memcpy(match.url_md5, files[i].url_id, MD5_LEN);
		if (scan->match_type == snippet)
			match.type = snippet;

		/* Add match to matches */
		add_match(-1, match, matches);
	}
	return file_count;
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
match_data fill_match(uint8_t *url_key, char *file_path, uint8_t *url_record)
{
	match_data match;
	match.selected = false;
	match.path_ln = 0;

	/* Extract fields from file record */
	if (url_key)
	{
		memcpy(match.url_md5, url_key, MD5_LEN);
		strcpy(match.file, file_path);
		match.path_ln = strlen(file_path);
	}
	else
		strcpy(match.file, "all");

	/* Extract fields from url record */
	extract_csv(match.vendor, (char *)url_record, 1, sizeof(match.vendor));
	extract_csv(match.component, (char *)url_record, 2, sizeof(match.component));
	extract_csv(match.version, (char *)url_record, 3, sizeof(match.version));
	extract_csv(match.release_date, (char *)url_record, 4, sizeof(match.release_date));
	extract_csv(match.license, (char *)url_record, 5, sizeof(match.license));
	extract_csv(match.purl[0], (char *)url_record, 6, sizeof(match.purl[0]));
	MD5((uint8_t *)match.purl[0], strlen(match.purl[0]), match.purl_md5[0]);

	extract_csv(match.url, (char *)url_record, 7, sizeof(match.url));
	strcpy(match.latest_version, match.version);

	flip_slashes(match.vendor);
	flip_slashes(match.component);
	flip_slashes(match.version);
	flip_slashes(match.url);
	flip_slashes(match.file);

	if (!*match.url || !*match.version || !*match.file || !*match.purl[0])
	{
		scanlog("Incomplete metadata for %s\n", file_path);
		memset(&match,0,sizeof(match));
		//return match_init();
	}

	return match;
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
 * @brief Add file record to matches
 * @param matches matches list
 * @param component_rank component ranking
 * @param file_md5 md5 hash of file
 */
void add_selected_file_to_matches(
	match_data *matches, component_name_rank *component_rank, int rank_id, uint8_t *file_md5)
{
	/* Create empty match item */
	struct match_data match;// = match_init();
	/* Fill match with component info */
	match = fill_match(component_rank[rank_id].url_id,
					   component_rank[rank_id].file,
					   (uint8_t *)component_rank[rank_id].url_record);
	match.type = file;

	/* Add file MD5 */
	memcpy(match.file_md5, file_md5, MD5_LEN);

	/* Add match to matches */
	add_match(0, match, matches);
}

/**
 * @brief load matches into the scan
 * @param scan scan data
 * @param matches matches list
 */
void load_matches(scan_data *scan, match_data *matches)
{
	strcpy(scan->line_ranges, "all");
	strcpy(scan->oss_ranges, "all");
	sprintf(scan->matched_percent, "100%%");

	/* Compile match ranges and fill up matched percent */
	int hits = 100;
	int matched_percent = 100;

	/* Get matching line ranges (snippet match) */
	if (scan->match_type == snippet)
	{
		hits = compile_ranges(scan);

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

		sprintf(scan->matched_percent, "%u%%", matched_percent);
	}

	uint32_t records = 0;

	/* Snippet and url match should look for the matching md5 in urls */
	if (scan->match_type != file)
	{
		records = ldb_fetch_recordset(NULL, oss_url, scan->match_ptr, false, handle_url_record, (void *)matches);
		scanlog("URL recordset contains %u records\n", records);
	}

	file_recordset *files = calloc(2 * FETCH_MAX_FILES, sizeof(file_recordset));
	records += ldb_fetch_recordset(NULL, oss_file, scan->match_ptr, false, collect_all_files, (void *)files);
	if (records)
	{
		if (engine_flags & DISABLE_BEST_MATCH)
		{
			records = add_all_files_to_matches(files, records, scan, matches);
		}
		else
		{
			component_name_rank component;
			scanlog("Inherited component hint from context: %s\n", *component_hint ? component_hint : "NULL");

			/* Query components for files with shortest path */
			component = shortest_paths_check(files, records);
			if (component.file[0] != 0)
			{
				add_selected_file_to_matches(matches, &component, 0, scan->match_ptr);
			}
		}
	}

	/* Add version ranges to selected match */
	add_versions(matches, files, records);

	free(files);

	if (!records)
		scanlog("Match type is 'none' after loading matches\n");
}

scan_data scan_aux;

bool match_process(match_data_t * fp1)
{
	struct match_data matches[3];
	fp1->type = MATCH_SNIPPET;
	memcpy(scan_aux.md5, fp1->file_md5, MD5_LEN);
	scan_aux.match_ptr = fp1->matchmap_reg;
	scan_aux.matched_percent[0]='0';
	scan_aux.line_ranges[0]='0';
	memset(matches, 0, sizeof(matches));
	
	load_matches(&scan_aux, matches);
	if (*matches[0].url && *matches[0].version && *matches[0].file && *matches[0].purl[0])
	{
		fp1->file = strdup(matches[0].file);
		fp1->latest_release_date = strdup(matches[0].latest_release_date);
		fp1->release_date = strdup(matches[0].release_date);
		fp1->url = strdup(matches[0].url);
		memcpy(fp1->url_md5, matches[0].url_md5, MD5_LEN);
		fp1->vendor = strdup(matches[0].vendor);
		fp1->component = strdup(matches[0].component);
		fp1->latest_version = strdup(matches[0].version);
		fp1->purls[0] = strdup(matches[0].purl[0]);
		fp1->purls_md5[0] = malloc(MD5_LEN);
		memcpy(fp1->purls_md5[0], matches[0].purl_md5, MD5_LEN);
		fp1->line_ranges = strdup(scan_aux.line_ranges);
		fp1->version = strdup(matches[0].version);
		fp1->matched_percent = strdup(scan_aux.matched_percent);
		fp1->oss_ranges = strdup(scan_aux.oss_ranges);
		strcpy(fp1->source_md5, scan_aux.source_md5);
	}
	return false;
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
		load_matches(scan, matches);
		list = match_list_init();
		match_data_t * match_new = malloc(sizeof(match_data_t));
		match_new->type = MATCH_FILE;

		match_new->file = strdup(matches[0].file);
		match_new->latest_release_date = strdup(matches[0].latest_release_date);
		match_new->release_date = strdup(matches[0].release_date);
		match_new->url = strdup(matches[0].url);	
		memcpy(match_new->url_md5, matches[0].url_md5, MD5_LEN);
		match_new->vendor = strdup(matches[0].vendor);
		match_new->component = strdup(matches[0].component);
		match_new->latest_version = strdup(matches[0].version);
		match_new->purls[0] = strdup(matches[0].purl[0]);
		match_new->purls_md5[0] = malloc(MD5_LEN);
		memcpy(match_new->purls_md5[0], matches[0].purl_md5, MD5_LEN);
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
			memcpy(&scan_aux, scan, sizeof(scan_data));
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
