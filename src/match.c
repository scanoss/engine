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

bool first_file = true;
const char *matchtypes[] = {"none", "url", "file", "snippet"};
bool match_extensions = false;

/* This script replaces \ with / */
void flip_slashes(char *data)
{
	int len = strlen(data);
	for (int i = 0; i < len ; i++) if (data[i] == '\\') data[i] = '/';
}

/* Output matches in JSON format via STDOUT */
void output_matches_json(match_data *matches, scan_data *scan_ptr)
{
	scan_data *scan = scan_ptr;

	/* Files not matching are only reported with -f plain */
	if (!matches) return;

	int match_counter = 0;

	flip_slashes(scan->file_path);

	/* Log slow query, if needed */
	slow_query_log(scan);

	/* Print comma separator */
	if (!quiet) if (!first_file) printf("  ,\n");
	first_file = false;

	/* Open file structure */
	json_open_file(scan->file_path);

	/* Print matches */
	if (matches)
	{
		bool selected = false;

		/* Print selected match */
		for (int i = 0; i < scan_limit && *matches[i].component; i++)
		{
			if (matches[i].selected)
			{
				print_json_match(scan, matches[i], &match_counter);
				selected = true;
			}
		}

		/* Print matches with version ranges first */
		if (!selected) for (int i = 0; i < scan_limit && *matches[i].component; i++)
			if (!matches[i].selected) if (strcmp(matches[i].version, matches[i].latest_version))
				print_json_match(scan, matches[i], &match_counter);

		/* Print matches without version ranges */
		if (!selected) for (int i = 0; i < scan_limit && *matches[i].component; i++)
			if (!matches[i].selected) if (!strcmp(matches[i].version, matches[i].latest_version))
				print_json_match(scan, matches[i], &match_counter);
	}

	/* Print no match */
	if (!match_counter) print_json_nomatch(scan);
	json_close_file();
}

match_data match_init()
{
	match_data match;
	*match.vendor = 0;
	*match.component = 0;
	*match.version = 0;
	*match.latest_version = 0;
	*match.url = 0;
	*match.file = 0;
	*match.release_date = 0;
	*match.license = 0;
	match.vulnerabilities = 0;
	match.path_ln = 0;
	match.selected = false;
	memset(match.url_md5, 0, MD5_LEN);
	memset(match.file_md5, 0, MD5_LEN);
	return match;
}
/* Add all files in recordset to matches */
int add_all_files_to_matches(file_recordset *files, int file_count, uint8_t *md5, match_data *matches)
{
	scanlog("Adding %d file records to matches\n", file_count);

	for (int i = 0; i < file_count; i++)
	{
		/* Create empty match item */
		struct match_data match = match_init();

		/* Get URL record */
		uint8_t *url_rec = calloc(LDB_MAX_REC_LN, 1);
		get_url_record(files[i].url_id, url_rec);

		/* Fill match with component info */
		match = fill_match(files[i].url_id, files[i].path, url_rec);
		free(url_rec);

		/* Add file MD5 */
		memcpy(match.file_md5, md5, MD5_LEN);
		memcpy(match.url_md5, files[i].url_id, MD5_LEN);

		/* Add match to matches */
		add_match(-1, match, matches, false);
	}
	return file_count;
}

bool ignored_asset_match(uint8_t *url_record)
{
	if (!ignored_assets) return false;

	bool found = false;

	char *asset = calloc(LDB_MAX_REC_LN, 1);
	extract_csv(asset, (char *) url_record, 2, LDB_MAX_REC_LN);
	strcat(asset, ",");

	if (strcasestr(ignored_assets, asset)) found = true;
	free(asset);

	if (found) scanlog("Component ignored: %s\n", url_record);

	return found;
}

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
	else strcpy(match.file, "all");

	/* Extract fields from url record */
	extract_csv(match.vendor,       (char *) url_record, 1, sizeof(match.vendor));
	extract_csv(match.component,    (char *) url_record, 2, sizeof(match.component));
	extract_csv(match.version,      (char *) url_record, 3, sizeof(match.version));
	extract_csv(match.release_date, (char *) url_record, 4, sizeof(match.release_date));
	extract_csv(match.license,      (char *) url_record, 5, sizeof(match.license));
	extract_csv(match.purl,         (char *) url_record, 6, sizeof(match.purl));
	extract_csv(match.url,          (char *) url_record, 7, sizeof(match.url));
	strcpy(match.latest_version, match.version);

	flip_slashes(match.vendor);
	flip_slashes(match.component);
	flip_slashes(match.version);
	flip_slashes(match.url);
	flip_slashes(match.file);

	if (!*match.url || !*match.version || !*match.file || !*match.purl)
	{
		scanlog("Incomplete metadata for %s\n", file_path);
		return match_init();
	}

	clean_versions(&match);
	return match;
}

int count_matches(match_data *matches)
{
	if (!matches)
	{
		scanlog("Match metadata is empty\n");
		return 0;
	}
	int c = 0;
	for (int i = 0; i < scan_limit && *matches[i].component; i++) c++;
	return c;
}

/* Adds match to matches */
void add_match(int position, match_data match, match_data *matches, bool component_match)
{

	/* Verify if metadata is complete */
	if (!*match.url || !*match.version || !*match.file || !*match.purl)
	{
		scanlog("Metadata is incomplete: %s,%s,%s,%s\n",match.purl,match.version,match.url,match.file);
		return;
	}

	int n = count_matches(matches);

	/* Attempt to place match among existing ones */
	bool placed = false;

	for (int i = 0; i < n; i++)
	{
		/* Are purls the same? */
		if (!strcmp(matches[i].purl, match.purl))
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

		/* Locate free position */
		int n = 0;

		/* Match position is given */
		if (position >= 0) n = position;

		/* Search for a free match position */
		else
		{
			for (n = 0; n < scan_limit; n++)
			{
				if (matches[n].path_ln > match.path_ln || !matches[n].path_ln) break;
			}
		}

		/* Copy match information */
		strcpy(matches[n].vendor, match.vendor);
		strcpy(matches[n].component, match.component);
		strcpy(matches[n].purl, match.purl);
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
	}
}

match_data *compile_matches(scan_data *scan)
{
	scan->match_ptr = scan->md5;

	/* Search for biggest snippet */
	if (scan->match_type == snippet)
	{
		scan->match_ptr = biggest_snippet(scan);
		if (!scan->match_ptr) return NULL;
		scanlog("%ld matches in snippet map\n", scan->matchmap_size);
	}

	/* Return NULL if no matches */
	if (!scan->match_ptr)
	{
		scan->match_type = none;
		scanlog("No matching file id\n");
		return NULL;
	}
	else
	{
		/* Log matching MD5 */
		for (int i = 0; i < MD5_LEN; i++) scanlog("%02x", scan->match_ptr[i]);
		scanlog(" selected\n");
	}

	/* Dump match map */
	if (debug_on) map_dump(scan);

	/* Gather and load match metadata */
	match_data *matches = NULL;

	scanlog("Starting match: %s\n",matchtypes[scan->match_type]);
	if (scan->match_type != none) matches = load_matches(scan);

	/* The latter could result in no matches */
	if (!matches) scan->match_type = none;
	scanlog("Final match: %s\n",matchtypes[scan->match_type]);

	return matches;
}

/* Add file record to matches */
void add_selected_file_to_matches(\
match_data *matches, component_name_rank *component_rank, int rank_id, uint8_t *file_md5)
{
	scanlog("Identified #%d: %s\n", rank_id, component_rank[rank_id].url_record);

	/* Create empty match item */
	struct match_data match = match_init();

	/* Fill match with component info */
	match = fill_match(component_rank[rank_id].url_id,\
			component_rank[rank_id].file,\
			(uint8_t *) component_rank[rank_id].url_record);

	/* Add file MD5 */
	memcpy(match.file_md5, file_md5, MD5_LEN);

	/* Add match to matches */
	add_match(0, match, matches, false);
}

match_data *load_matches(scan_data *scan)
{
	strcpy(scan->line_ranges, "all");
	strcpy(scan->oss_ranges, "all");
	sprintf(scan->matched_percent,"100%%");

	/* Compile match ranges and fill up matched percent */
	int hits = 100;
	int matched_percent = 100;

	/* Get matching line ranges (snippet match) */
	if (scan->match_type == snippet)
	{
		hits = compile_ranges(scan);

		float percent = (hits * 100) / scan->total_lines;
		if (hits) matched_percent = floor(percent);
		if (matched_percent > 100) matched_percent = 100;

		scanlog("compile_ranges returns %d hits\n", hits);
		if (!hits) return NULL;

		sprintf(scan->matched_percent,"%u%%", matched_percent);
	}

	/* Init matches structure */
	struct match_data *matches = calloc(sizeof(match_data), scan_limit);
	for (int i = 0; i < scan_limit; i++)
	{
		matches[i].type = scan->match_type;
		matches[i].selected = false;
		matches[i].scandata = scan;
		memset(matches[i].file_md5, 0, MD5_LEN);
		memset(matches[i].url_md5, 0, MD5_LEN);
	}

	uint32_t records = 0;

	/* Snippet and url match should look for the matching md5 in urls */
	if (scan->match_type != file)
	{
		records = ldb_fetch_recordset(NULL, oss_url, scan->match_ptr, false, handle_url_record, (void *) matches);
		scanlog("URL recordset contains %u records\n", records);
	}

	if (!records)
	{

		file_recordset *files = calloc(2 * FETCH_MAX_FILES, sizeof(file_recordset));
		records = ldb_fetch_recordset(NULL, oss_file, scan->match_ptr, false, collect_all_files, (void *) files);

		if (records)
		{
			if (engine_flags & DISABLE_BEST_MATCH)
			{
				records = add_all_files_to_matches(files, records, scan->match_ptr, matches);
			}
			else
			{

				char new_component_hint[MAX_FIELD_LN] = "\0";
				component_name_rank *component_rank = calloc(sizeof(struct component_name_rank), rank_items);
				scanlog("Inherited component hint from context: %s\n", *component_hint ? component_hint : "NULL");

				/* Try the contextual component_hint, if any */
				int selected = seek_component_hint_in_path(files, records, component_hint, component_rank);

				/* Get new component hint and try that instead */
				if (selected < 0)
				{
					/* Mark external files and collect new_component_hint */
					external_component_hint_in_path(files, records, new_component_hint, component_rank);

					/* Attempt to identify hints in start of path and component name */
					selected = seek_component_hint_in_path(files, records, new_component_hint, component_rank);
				}

				/* Attempt to identify components from paths starting with the component name */
				if (selected < 0)
				{
					selected = seek_component_hint_in_path_start(files, records, component_rank);
				}

				if (selected >= 0)
				{
					add_selected_file_to_matches(matches, component_rank, selected, scan->match_ptr);

					/* Update component_hint for the next file */
					strcpy(component_hint, component_rank[selected].component);
				}

				/* Attempt matching selecting the shortest paths */
				else
				{
					/* Init path ranking */
					path_ranking path_rank[rank_items];
					init_path_ranking(path_rank);

					/* Attempt matching start of short paths with their respective components names */
					bool hint_found = component_hint_from_shortest_paths(\
							files, records,\
							component_hint, new_component_hint,\
							component_rank,\
							path_rank\
							);

					/* Otherwise try again without passing hints, just ranking from shortest paths */
					if (!hint_found) hint_found = component_hint_from_shortest_paths(\
							files, records,\
							"", "",\
							component_rank,\
							path_rank\
							);

					/* Select the best component hint from the collected rank */
					if (hint_found) select_best_component_from_rank(component_rank, component_hint);

					/* Show component hint, if found */
					if (hint_found) scanlog("Component hint = %s/%s\n", *vendor_hint ? vendor_hint : "?", component_hint);

					/* Add relevant files to matches */
					if (!add_files_to_matches(files, records, component_hint, scan->match_ptr, matches, false))
					{
						/* If this did not work, attempt finding the component name in the path */
						selected = seek_component_hint_in_path_start(files, records, component_rank);

						/* If still no luck, forget about hint and add all files to matches */
						if (selected < 0)
						{
							add_files_to_matches(files, records, component_hint, scan->match_ptr, matches, true);
							selected = 0;
						}

						/* Add file to matches */
						add_selected_file_to_matches(matches, component_rank, selected, scan->match_ptr);

						/* Update component_hint for the next file */
						strcpy(component_hint, component_rank[selected].component);
					}
				}
				free(component_rank);
			}
		}
		/* Add version ranges to selected match */
		add_versions(scan, matches, files, records);

		free(files);
	}

	if (records) return matches;

	if (matches) free(matches);

	scanlog("Match type is 'none' after loading matches\n");
	return NULL;
}
