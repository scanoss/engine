// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/scan.c
 *
 * Scan-related subroutines
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

#include "scan.h"
#include "rank.h"
#include "snippets.h"
#include "match.h"
#include "query.h"
#include "file.h"
#include "util.h"
#include "parse.h"
#include "debug.h"
#include "psi.h"
#include "limits.h"
#include "blacklist.h"
#include "winnowing.h"
#include "ldb.h"

char *sbom = NULL;
char *blacklisted_assets = NULL;

/* Calculate and write source wfp md5 in scan->source_md5 */
static void calc_wfp_md5(scan_data *scan)
{
	uint8_t tmp_md5[16];
	get_file_md5(scan->file_path, tmp_md5);
	char *tmp_md5_hex = md5_hex(tmp_md5);
	strcpy(scan->source_md5, tmp_md5_hex);
	free(tmp_md5_hex);
}

/* Init scan structure */
scan_data scan_data_init(char *target)
{
	scan_data scan;
	scan.md5 = calloc (MD5_LEN,1);
	scan.file_path = calloc(LDB_MAX_REC_LN, 1);
	strcpy(scan.file_path, target);

	scan.file_size = calloc(LDB_MAX_REC_LN, 1);

	strcpy(scan.source_md5, "00000000000000000000000000000000\0");
	scan.hashes = malloc(MAX_FILE_SIZE);
	scan.lines  = malloc(MAX_FILE_SIZE);
	scan.hash_count = 0;
	scan.timer = 0;
	scan.preload = false;
	scan.total_lines = 0;
	scan.matchmap = calloc(MAX_FILES, sizeof(matchmap_entry));
	scan.matchmap_size = 0;
	scan.match_type = none;
	scan.preload = false;
	*scan.snippet_ids = 0;

	/* Get wfp MD5 hash */
	if (extension(target)) if (!strcmp(extension(target), "wfp")) calc_wfp_md5(&scan);

	return scan;
}

static void scan_data_reset(scan_data *scan)
{
	*scan->file_path = 0;
	*scan->file_size = 0;
	scan->hash_count = 0;
	scan->timer = 0;
	scan->total_lines = 0;
	scan->matchmap_size = 0;
	scan->hash_count = 0;
	scan->match_type = none;
	*scan->snippet_ids = 0;
}

void scan_data_free(scan_data scan)
{
	free(scan.md5);
	free(scan.file_path);
	free(scan.file_size);
	free(scan.hashes);
	free(scan.lines);
	free(scan.matchmap);
}

/* Returns true if md5 is the md5sum for NULL */
static bool zero_bytes (uint8_t *md5)
{
	uint8_t empty[] = "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e";

	for (int i = 0; i < 15; i++)
		if (md5[i] != empty[i]) return false;

	return true;
}

/* Performs component and file comparison */
static matchtype ldb_scan_file(uint8_t *fid) {
			
	scanlog("Checking entire file\n");
	
	if (zero_bytes(fid)) return none;
	
	matchtype match_type = none;

	if (ldb_key_exists(oss_component, fid)) match_type = url;
	else if (ldb_key_exists(oss_file, fid)) match_type = file;

	return match_type;
}

bool assets_match(match_data match)
{
	if (!sbom) return false;

	bool found = false;	

	char *asset = calloc(LDB_MAX_REC_LN, 1);
	sprintf(asset, "%s,", match.component);

	if (strstr(sbom, asset)) found = true;
	free(asset);

	return found;
}

bool blacklist_match(uint8_t *url_record)
{
	if (!blacklisted_assets) return false;

	bool found = false;	

	char *asset = calloc(LDB_MAX_REC_LN, 1);
	extract_csv(asset, (char *) url_record, 2, LDB_MAX_REC_LN);
	strcat(asset, ",");

	if (strcasestr(blacklisted_assets, asset)) found = true;
	free(asset);

	if (found) scanlog("Component blacklisted: %s\n", url_record);

	return found;
}

void normalise_version(char *version, char *component)
{
	/* Remove leading component name from version */
	if (stristart(version, component))
	{
		memmove(version, version + strlen(component), strlen(version + strlen(component)) + 1);
		if (*version == '-') memmove(version, version + 1, strlen(version + 1) + 1);
	}

	/* Remove leading v from version */
	if (*version == 'v') memmove(version, version + 1, strlen(version) + 1);

	/* Remove trailing ".orig" from version */
	char *orig = strstr(version, ".orig");
	if (orig) *orig = 0;
}

void clean_versions(match_data *match)
{
	normalise_version(match->version, match->component);
	normalise_version(match->latest_version, match->component);
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

/* Returns true if rec_ln is longer than everything else in "matches"
	also, update position with the position of a longer path */
bool longer_path_in_set(match_data *matches, int total_matches, int rec_ln, int *position)
{
  if (scan_limit > total_matches) return false;

	/* Search for a longer path than rec_ln */
	for (int i = 0; i < total_matches; i++)
	{
		if (matches[i].path_ln > rec_ln)
		{
			*position = i;
			return false;
		}
	}

	return true;
}

bool handle_url_record(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{
	if (!datalen && datalen >= MAX_PATH) return false;

	uint8_t data[MAX_PATH] = "\0";
	memcpy(data, raw_data, datalen);
	data[datalen] = 0;

	match_data *matches = (match_data*) ptr;
	struct match_data match = match_init();

	/* Exit if we have enough matches */
	int total_matches = count_matches(matches);
	if (total_matches >= scan_limit) return true;

	match = fill_match(NULL, NULL, data);

	/* Save match component id */
	memcpy(match.url_md5, key, LDB_KEY_LN);
	memcpy(match.url_md5 + LDB_KEY_LN, subkey, subkey_ln);
	memcpy(match.file_md5, match.url_md5, MD5_LEN);

	add_match(-1, match, matches, true);

	return false;
}

/* Determine if a file is to be skipped based on extension or path content */
bool skip_file_path(char *path, match_data *matches)
{
	bool unwanted = false;

	/* Skip blacklisted path */
	if (unwanted_path(path)) unwanted = true;

	/* Skip blacklisted extension */
	else if (extension(path) && blacklisted_extension(path))
	{
		scanlog("Blacklisted extension\n");
		unwanted = true;
	}

	/* Compare extension of matched file with scanned file */
	else if (match_extensions)
	{
		char *oss_ext = extension(path);
		char *my_ext = extension(matches->scandata->file_path);
		if (oss_ext) if (my_ext) if (strcmp(oss_ext, my_ext))
		{
			scanlog("Matched file extension does not match source\n");
			unwanted = true;
		}
	}

	return unwanted;
}

bool collect_all_files(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{

	/* Leave if FETCH_MAX_FILES is reached */
	if (iteration >= FETCH_MAX_FILES) return true;

	/* Ignore path lengths over the limit */
	if (!datalen || datalen >= (MD5_LEN + MAX_FILE_PATH)) return false;

	/* Copy data to memory */
	file_recordset *files = ptr;
	int path_ln = datalen - MD5_LEN;
	files[iteration].path_ln = path_ln;
	memcpy(files[iteration].url_id, raw_data, MD5_LEN);
	memcpy(files[iteration].path, raw_data + MD5_LEN, path_ln);
	files[iteration].path[path_ln] = 0;

	scanlog("#%d File %s\n", iteration, files[iteration].path);
	return false;
}

/* Evaluate file and decide whether or not to add it to *matches */
void consider_file_record(\
		uint8_t *url_id,\
		char *path,\
		match_data *matches,\
		char *component_hint,\
		uint8_t *match_md5)
{
	/* Skip unwanted paths */
	if (skip_file_path(path, matches)) return;

	struct match_data match = match_init();

	int total_matches = count_matches(matches);

	/* If we have a full set, and this path is longer than others, skip it*/
	int position = -1;
	if (longer_path_in_set(matches, total_matches, strlen(path), &position)) return;

	/* Check if matched file is a blacklisted extension */
	if (extension(path))
	{
		if (blacklisted_extension(path))
		{
			scanlog("Blacklisted extension\n");
			return;
		}
	}

	uint8_t *url = calloc(LDB_MAX_REC_LN, 1);
	get_url_record(url_id, url);
	if (*url)
	{
		match = fill_match(url_id, path, url);

		/* Save match file id */
		memcpy(match.file_md5, match_md5, MD5_LEN);
	}
	else
	{
		scanlog("Orphan file\n");
		return;
	}

	add_match(position, match, matches, false);
	free(url);
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

	/* Snippet and component match should look for the matching md5 in urls */
	if (scan->match_type != file)
	{
		records = ldb_fetch_recordset(NULL, oss_component, scan->match_ptr, false, handle_url_record, (void *) matches);
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
		free(files);
	}

	if (records) return matches;

	if (matches) free(matches);

	scanlog("Match type is 'none' after loading matches\n");
	return NULL;
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

/* Scans a wfp file with winnowing fingerprints */
int wfp_scan(scan_data *scan)
{
	char * line = NULL;
	size_t len = 0;
	ssize_t lineln;
	uint8_t *rec = calloc(LDB_MAX_REC_LN, 1);
	scan->preload = true;

	/* Open WFP file */
	FILE *fp = fopen(scan->file_path, "r");
	if (fp == NULL)
	{
		fprintf(stdout, "E017 Cannot open target");
		return EXIT_FAILURE;
	}
	bool read_data = false;

	/* Read line by line */
	while ((lineln = getline(&line, &len, fp)) != -1)
	{
		trim(line);

		bool is_component = (memcmp(line, "component=", 4) == 0);
		bool is_file = (memcmp(line, "file=", 5) == 0);
		bool is_wfp = (!is_file && !is_component);

		/* Scan previous file */
		if ((is_component || is_file) && read_data) ldb_scan(scan);

		/* Parse file information with format: file=MD5(32),file_size,file_path */
		if (is_file)
		{
			scan_data_reset(scan);
			const int tagln = 5; // len of 'file='

			/* Get file MD5 */
			char *hexmd5 = calloc(MD5_LEN * 2 + 1, 1);
			memcpy(hexmd5, line + tagln, MD5_LEN * 2);
			ldb_hex_to_bin(hexmd5, MD5_LEN * 2, scan->md5);
			free(hexmd5);

			/* Extract fields from file record */
			strcpy((char *)rec, line + tagln + (MD5_LEN * 2) + 1);
			extract_csv(scan->file_size, (char *)rec, 1, LDB_MAX_REC_LN);
			extract_csv(scan->file_path, (char *)rec, 2, LDB_MAX_REC_LN);

			read_data = true;
		}

		/* Save hash/es to memory. Parse file information with format:
		   linenr=wfp(6)[,wfp(6)]+ */

		if (is_wfp && (scan->hash_count < MAX_HASHES_READ))
		{
			/* Split string by the equal and commas */
			int line_ln = strlen(line);
			for (int e = 0; e < line_ln; e++) if (line[e]=='=' || line[e]==',') line[e] = 0;

			/* Extract line number */
			int line_nr = atoi(line);

			/* Move pointer to the first hash */
			char *hexhash = line + strlen(line) + 1;

			/* Save all hashes in the present line */
			while (*hexhash) {

				/* Convert hash to binary */
				ldb_hex_to_bin(hexhash, 8, (uint8_t *)&scan->hashes[scan->hash_count]);
				uint32_reverse((uint8_t *)&scan->hashes[scan->hash_count]);

				/* Save line number */
				scan->lines[scan->hash_count] = line_nr;

				/* Move pointer to the next hash */
				hexhash += strlen(hexhash) + 1;

				scan->hash_count++;
			}
		}
	}

	/* Scan the last file */
	if (read_data) ldb_scan(scan);

	fclose(fp);
	if (line) free(line);
	free(rec);

	return EXIT_SUCCESS;
}

/* Scans a file and returns JSON matches via STDOUT
   scan structure can be already preloaded (.wfp scan)
   otherwise, it will be loaded here (scanning a physical file) */
bool ldb_scan(scan_data *scan)
{
	bool skip = false;

	scan->matchmap_size = 0;
	scan->match_type = none;
	scan->timer = microseconds_now();

	/* Get file length */
	uint64_t file_size;
	if (scan->preload) file_size = atoi(scan->file_size);
	else file_size = get_file_size(scan->file_path);

	/* Error reading file */
	if (file_size < 0) ldb_error("Cannot access file");

	/* Calculate MD5 hash (if not already preloaded) */
	if (!scan->preload) get_file_md5(scan->file_path, scan->md5);

	if (extension(scan->file_path))
		if (blacklisted_extension(scan->file_path)) skip = true;

	/* Ignore <=1 byte */
	if (file_size <= MIN_FILE_SIZE) skip = true;

	if (!skip)
	{
		/* Scan full file */
		scan->match_type = ldb_scan_file(scan->md5);

		/* If no match, scan snippets */
		if (scan->match_type == none)
		{
			/* Load snippets into scan data */
			if (!scan->preload)
			{
				/* Read file into memory */
				char *src = calloc(MAX_FILE_SIZE, 1);
				if (file_size < MAX_FILE_SIZE) read_file(src, scan->file_path, 0);

				/* Determine if file is to skip snippet search */
				if (!skip_snippets(src, file_size))
				{
					/* Load wfps into scan structure */
					scan->hash_count = winnowing(src, scan->hashes, scan->lines, MAX_FILE_SIZE);
					if (scan->hash_count) scan->total_lines = scan->lines[scan->hash_count - 1];
				}
				free(src);
			}
			else if (scan->hash_count) scan->total_lines = scan->lines[scan->hash_count - 1];

			/* Perform snippet scan */
			if (scan->total_lines) scan->match_type = ldb_scan_snippets(scan);

			else scanlog("File skipped\n");
		}
	}

	/* Compile matches */
	match_data *matches = compile_matches(scan);

	if (scan->match_type != none)
	{
		int total_matches = count_matches(matches);

		/* Debug match info */
		scanlog("%d matches compiled:\n", total_matches);
		if (debug_on) for (int i = 0; i < total_matches; i++)
			scanlog("%s/%s, %s\n", matches[i].vendor, matches[i].component, matches[i].file);
		scanlog("\n", total_matches);

		/* Matched asset in SBOM.json? */
		for (int i = 0; i < total_matches; i++)
		{
			if (assets_match(matches[i]))
			{
				scanlog("Asset matched\n");
				if (matches) free(matches);
				matches = NULL;
				scan->match_type = none;
				break;
			}
		}

		/* Perform post scan intelligence */
		if (scan->match_type != none)
		{
			scanlog("Starting post-scan analysis\n");
			post_scan(matches);
		}
	}

	/* Output matches */
	scanlog("Match output starts\n");
	output_matches_json(matches, scan);

	if (matches) free(matches);
	scan_data_reset(scan);
	return true;
}
