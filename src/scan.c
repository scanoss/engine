// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/scan.c
 *
 * Scan-related subroutines
 *
 * Copyright (C) 2018-2020 SCANOSS.COM
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

scan_data scan_data_init()
{
	scan_data scan;
	scan.md5 = calloc (MD5_LEN,1);
	scan.file_path = calloc(LDB_MAX_REC_LN, 1);
	scan.file_size = calloc(LDB_MAX_REC_LN, 1);
	scan.hashes = malloc(MAX_FILE_SIZE);
	scan.lines  = malloc(MAX_FILE_SIZE);
	scan.hash_count = 0;
	scan.timer = 0;
	scan.preload = false;
	scan.total_lines = 0;
	scan.matchmap = calloc(MAX_FILES * MAP_REC_LEN, 1);
	scan.matchmap_ptr = 0;
	scan.match_type = none;
	scan.preload = false;
	return scan;
}

void scan_data_reset(scan_data *scan)
{
	*scan->file_path = 0;
	*scan->file_size = 0;
	scan->hash_count = 0;
	scan->total_lines = 0;
	scan->matchmap_ptr = 0;
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

char *parse_sbom(char *filepath);

/* Returns true if md5 is the md5sum for NULL */
bool zero_bytes (uint8_t *md5)
{
	uint8_t empty[] = "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e";

	for (int i = 0; i < 15; i++)
		if (md5[i] != empty[i]) return false;

	return true;
}

/* Performs component and file comparison */
matchtype ldb_scan_file(uint8_t *fid) {
			
	scanlog("Checking entire file\n");
	
	if (zero_bytes(fid)) return none;
	
	matchtype match_type = none;

	if (ldb_key_exists(oss_component, fid)) match_type = component;
	else if (ldb_key_exists(oss_file, fid)) match_type = file;

	return match_type;
}

void adjust_tolerance(scan_data *scan)
{
	bool skip = false;
	uint32_t wfpcount = scan->hash_count;

	if (!wfpcount) skip = true;
	else if (scan->lines[wfpcount-1] < 10) skip = true;

	if (skip) min_match_lines = 1;
	else
	{
		/* Range tolerance is the maximum amount of non-matched lines accepted
		   within a matched range. This goes from 15 in small files to 5 in large files */

		range_tolerance = 15 - floor(wfpcount / 20);
		if (range_tolerance < 5) range_tolerance = 5;

		/* Min matched lines is the number of matched lines in total under which the result
		   is ignored. This goes from 3 in small files to 10 in large files */

		min_match_lines = 3 + floor(wfpcount / 5);
		if (min_match_lines > 10) min_match_lines = 10;
	}

	scanlog("Tolerance: range=%d, lines=%d, wfpcount=%u\n", range_tolerance, min_match_lines, wfpcount);
}

/* Handler function to collect all file ids */
bool get_all_file_ids(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	uint8_t *record = (uint8_t *) ptr;
	if (datalen)
	{
		uint32_t size = uint32_read(record);

		/* End recordset fetch if MAX_QUERY_RESPONSE is reached */
		if (size + datalen + 4 >= MAX_QUERY_RESPONSE) return true;

		/* End recordeet fetch if MAX_FILES are reached for the snippet */
		if ((WFP_REC_LN * MAX_FILES) <= (size + datalen)) return true;

		/* Save data and update dataln */
		memcpy(record + size + 4, data, datalen);
		uint32_write(record, size + datalen);
	}
	return false;
}

/* Query all wfp and add resulting file ids to the matchmap
   matchmap is a series of fixed-length records with the following structure:
   [MD5(16)][hits(2)][range1(4)]....[rangeN(4)][lastwfp(4)] */

matchtype ldb_scan_snippets(scan_data *scan) {

	if (!scan->hash_count) return none;
	scanlog("Checking snippets\n");

	adjust_tolerance(scan);

	uint32_t line = 0;
	uint32_t prev_line = 1;
	uint8_t *wfp_ptr;
	uint8_t wfp[4];
	uint32_t from = 0;
	uint32_t to = 0;

	uint8_t *all_md5 = malloc(MAX_QUERY_RESPONSE);
	uint32_t all_md5_ln = 0;
	uint16_t hits = 0;
	int consecutive = 0;

	/* Limit snippets to be scanned  */
	if (scan->hash_count > MAX_SNIPPETS_SCANNED) scan->hash_count = MAX_SNIPPETS_SCANNED;

	/* Compare each wfp */
	for (long i = 0; i < scan->hash_count; i++)
	{
		/* Read line number and wfp */
		line = scan->lines[i];
		wfp_ptr = (uint8_t*)&scan->hashes[i];
		wfp[0]=wfp_ptr[3];
		wfp[1]=wfp_ptr[2];
		wfp[2]=wfp_ptr[1];
		wfp[3]=wfp_ptr[0];

		/* Get all file IDs for given wfp */
		uint32_write(all_md5, 0);
		ldb_fetch_recordset(NULL, oss_wfp, wfp, false, get_all_file_ids, (void *) all_md5);
		all_md5_ln = uint32_read(all_md5);

		uint8_t *md5_records = all_md5 + 4;
		if (all_md5_ln > (WFP_POPULARITY_THRESHOLD * WFP_REC_LN)) all_md5_ln = 0;

		scanlog("Snippet %02x%02x%02x%02x (line %d) -> %u hits\n", wfp[0], wfp[1], wfp[2], wfp[3], line, all_md5_ln / WFP_REC_LN);

		/* If a snippet brings more than "score" result by "hits" times in a row, we skip "jump" snippets */
		if (scan->hash_count > consecutive_threshold)
		{
			if (all_md5_ln > consecutive_score)
			{
				if (++consecutive >= consecutive_hits)
				{
					i += consecutive_jump;
					consecutive = 0;
				}
			}
		}

		/* Recurse each record from the wfp table */
		for (int n = 0; n < all_md5_ln; n += WFP_REC_LN)
		{
			/* Retrieve an MD5 from the recordset */
			memcpy(scan->md5, md5_records + n, MD5_LEN);

			/* The md5 is followed by the line number where the wfp hash was seen */
			uint8_t *oss_line = md5_records + n + MD5_LEN;

			/* Check if md5 already exists in map */
			long found = -1;
			for (long t=0; t < scan->matchmap_ptr; t++)
			{
				if (md5cmp(scan->matchmap + t * MAP_REC_LEN, scan->md5))
				{
					found = t;
					break;
				}
			}

			/* Map record: [MD5(16)][hits(2)][range1(6)]....[rangeN(6)][lastwfp(4)]
			   where range contains start(2) to(2) start_on_external_file(2) */
			if (found < 0)
			{
				/* Not found. Add MD5 to map */
				if (scan->matchmap_ptr >= MAX_FILES) break;
				memcpy(scan->matchmap + (scan->matchmap_ptr * MAP_REC_LEN), scan->md5, MD5_LEN);
				found = scan->matchmap_ptr;
			}

			/* Search for the right range */
			uint32_t record_offset = found * MAP_REC_LEN;
			uint32_t ranges_offset = record_offset + WFP_REC_LN; // We skip MD5(16) + hits (2)
			hits = uint16_read(scan->matchmap + record_offset + MD5_LEN);
			to = line;
			uint8_t *lastwfp = scan->matchmap + ranges_offset + 6 * MAX_MAP_RANGES;

			for (uint32_t t = 0; t < MAX_MAP_RANGES; t++)
			{
				from = uint16_read (scan->matchmap + ranges_offset + 6 * t);
				to   = uint16_read (scan->matchmap + ranges_offset + 6 * t + 2);

				/* New range */
				if (from == 0 && to == 0)
				{
					/* Update from and to */
					uint16_write (scan->matchmap + ranges_offset + 6 * t, prev_line);
					uint16_write (scan->matchmap + ranges_offset + 6 * t + 2, line);
					memcpy(scan->matchmap + ranges_offset + 6 * t + 4, oss_line, 2);
					break;
				}

				/* Another hit in the same line, no need to expand range */
				else if (to == line)
				{
					/* Update hits count (if we are not hitting the same wfp again) */
					if (memcmp(wfp,lastwfp,4))
					{
						uint16_write (scan->matchmap + record_offset + MD5_LEN, (uint16_t) (1 + hits));
						memcpy(lastwfp,wfp,4);
					}
					break;
				}

				/* Increase range */
				else if ((prev_line - to) < range_tolerance)
				{
					/* Update to */
					uint16_write (scan->matchmap + (ranges_offset + 6 * t + 2), line);
					break;
				}
			}

			/* Update hits count (if we are not hitting the same wfp again) */
			if (to != line)
			{	
				if (memcmp(wfp,lastwfp,4))
				{
					uint16_write (scan->matchmap + record_offset + MD5_LEN, (uint16_t) (1 + hits));
					memcpy(lastwfp,wfp,4);
				}
			}
			if (found == scan->matchmap_ptr) scan->matchmap_ptr++;
		}
		prev_line = line;
	}

	free(all_md5);

	if (scan->matchmap_ptr) return snippet;
	scanlog("Snippet scan has no matches\n");
	return none;
}

int ldb_matched_percent(matchtype match_type, int hits, unsigned int total) {
	int out;
	if (match_type == snippet)
		out = ((total > 0 ? ((100 * hits) / total) : 0));
	else
		out = 100;
	return out;
}

/* Compiles list of line ranges, returning total number of hits (lines matched) */
uint32_t compile_ranges(uint8_t *matchmap_matching, char *ranges, char *oss_ranges) {

	if (uint16_read(matchmap_matching + MD5_LEN) < 2) return 0;
	int hits = 0;

	/* Lowest tolerance simply requires selecting the higher match count */
	if (min_match_lines == 1)
	{
		strcpy(ranges, "N/A");
		strcpy(oss_ranges, "N/A");
		return uint16_read(matchmap_matching + MD5_LEN);
	}

	ranges [0] = 0;
	oss_ranges [0] = 0;

	for (uint32_t i = 0; i < MAX_MAP_RANGES; i++) {

		long from     = uint16_read (matchmap_matching + 16 + 2 + i * 6);
		long to       = uint16_read (matchmap_matching + 16 + 2 + i * 6 + 2);
		long oss_from = uint16_read (matchmap_matching + 16 + 2 + i * 6 + 4);

		if (to < 1) break;

		/* Add range as long as the minimum number of match lines is reached */
		if ((to - from) >= min_match_lines) {
			sprintf (ranges + strlen(ranges), "%ld-%ld,", from, to);
			sprintf (oss_ranges + strlen(oss_ranges), "%ld-%ld,", oss_from, to - from + oss_from);
			hits += (to - from);
		}
	}

	/* Remove last comma */
	if (strlen(ranges) > 0) ranges[strlen(ranges) - 1] = 0;
	else strcpy(ranges, "all");

	if (strlen(oss_ranges) > 0) oss_ranges[strlen(oss_ranges) - 1] = 0;
	else strcpy(oss_ranges, "all");

	return hits;
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

bool blacklist_match(uint8_t *component_record)
{
	if (!blacklisted_assets) return false;

	bool found = false;	

	char *asset = calloc(LDB_MAX_REC_LN, 1);
	extract_csv(asset, (char *) component_record, 2, LDB_MAX_REC_LN);
	strcat(asset, ",");

	if (strcasestr(blacklisted_assets, asset)) found = true;
	free(asset);

	if (found) scanlog("Component blacklisted: %s\n", component_record);

	return found;
}

match_data match_init()
{
	match_data match;
	*match.lines = 0;
	*match.vendor = 0;
	*match.component = 0;
	*match.version = 0;
	*match.latest_version = 0;
	*match.lines = 0;
	*match.oss_lines = 0;
	*match.url = 0;
	*match.file = 0;
	*match.matched = 0;
	*match.size = 0;
	match.path_ln = 0;
	match.selected = false;
	memcpy(match.component_md5, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", MD5_LEN);
	memcpy(match.file_md5, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", MD5_LEN);
	return match;
}

match_data fill_match(uint8_t *file_record, uint8_t *component_record)
{
	match_data match;
	match.selected = false;
	match.path_ln = 0;

	/* Extract fields from file record */
	if (file_record)
	{
		memcpy(match.component_md5, file_record, MD5_LEN);
		extract_csv(match.size, (char *) file_record + MD5_LEN, 1, sizeof(match.size));
		extract_csv(match.file, (char *) file_record + MD5_LEN, 2, sizeof(match.file));
		match.path_ln = strlen((char *) file_record + MD5_LEN);
	}
	else
	{
		strcpy(match.size, "N/A");
		strcpy(match.file, "all");
	}

	/* Extract fields from url record */
	extract_csv(match.vendor,    (char *) component_record, 1, sizeof(match.vendor));
	extract_csv(match.component, (char *) component_record, 2, sizeof(match.component));
	extract_csv(match.version,   (char *) component_record, 3, sizeof(match.version));
	extract_csv(match.url,       (char *) component_record, 4, sizeof(match.url));
	strcpy(match.latest_version, match.version);

	flip_slashes(match.vendor);
	flip_slashes(match.component);
	flip_slashes(match.version);
	flip_slashes(match.url);
	flip_slashes(match.file);

	if (!*match.vendor || !*match.component || !*match.url || !*match.version || !*match.file || !*match.size)
		return match_init();

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
void add_match(match_data match, int total_matches, match_data *matches, bool component_match)
{

	/* Verify if metadata is complete */
	if (!*match.vendor || !*match.component || !*match.url || !*match.version || !*match.file || !*match.size)
	{
		scanlog("Metadata is incomplete: %s,%s,%s,%s,%s,%s\n",match.vendor,match.component,match.version,match.size,match.url,match.file);
		return;
	}

	int n = count_matches(matches);

	/* Attempt to place match among existing ones */
	bool placed = false;

	for (int i = 0; i < n; i++)
	{
		/* Are vendor/component the same? */
		if (!strcmp(matches[i].vendor, match.vendor) &&
				!strcmp(matches[i].component, match.component))
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
		for (int n = 0; n < scan_limit; n++)
		{
			if (matches[n].path_ln > match.path_ln || !matches[n].path_ln)
			{
				strcpy(matches[n].vendor, match.vendor);
				strcpy(matches[n].component, match.component);
				strcpy(matches[n].version, match.version);
				strcpy(matches[n].latest_version, match.latest_version);
				strcpy(matches[n].url, match.url);
				strcpy(matches[n].file, match.file);
				strcpy(matches[n].size, match.size);
				memcpy(matches[n].component_md5, match.component_md5, MD5_LEN);
				memcpy(matches[n].file_md5, match.file_md5, MD5_LEN);
				matches[n].path_ln = match.path_ln;
				matches[n].selected = match.selected;
				break;
			}
		}
	}
}

/* Returns true if rec_ln is longer than everything else in "matches" */
bool longer_path_in_set(match_data *matches, int total_matches, int rec_ln)
{
	if (scan_limit > total_matches) return false;

	int max_ln = 0;

	for (int i = 0; i < total_matches; i++)
	{
		if (matches[i].path_ln > max_ln) max_ln = matches[i].path_ln;
	}

	return (rec_ln > max_ln);
}

bool handle_component_record(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
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

	match = fill_match(NULL, data);

	/* Save match component id */
	memcpy(match.component_md5, key, LDB_KEY_LN);
	memcpy(match.component_md5 + LDB_KEY_LN, subkey, subkey_ln);
	memcpy(match.file_md5, match.component_md5, MD5_LEN);

	add_match(match, total_matches, matches, true);

	return false;
}
bool handle_file_record(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{
	if (!datalen && datalen >= MAX_PATH) return false;

	uint8_t data[MAX_PATH] = "\0";
	memcpy(data, raw_data, datalen);
	data[datalen] = 0;

	match_data *matches = (match_data*) ptr;

	/* Skip unwanted paths */
	if (skip_file_path(data, datalen, matches)) return false;

	struct match_data match = match_init();

	int total_matches = count_matches(matches);

	/* If we have a full set, and this path is longer than others, skip it*/
	if (longer_path_in_set(matches, total_matches, datalen)) return false;

	/* Check if matched file is a blacklisted extension */
	if (blacklisted((char *) data + MD5_LEN)) return false;

	/* If component does not exist (orphan file) skip it */
	if (!ldb_key_exists(oss_component, data))
	{
		scanlog("Orphan file\n");
		return false;
	}

	uint8_t *component = calloc(LDB_MAX_REC_LN, 1);
	get_component_record(data, component);
	if (*component)
	{
		match = fill_match(data, component);

		/* Save match file id */
		memcpy(match.file_md5, key, LDB_KEY_LN);
		memcpy(match.file_md5 + LDB_KEY_LN, subkey, subkey_ln);
	}
	else scanlog("No component data found\n");

	add_match(match, total_matches, matches, false);
	free(component);

	return false;
}

struct match_data *prefill_match(scan_data *scan, char *lines, char *oss_lines, int matched_percent)
{
	struct match_data *matches = calloc(sizeof(match_data), scan_limit);
	for (int i = 0; i < scan_limit; i++)
	{
		matches[i].type = scan->match_type;
		strcpy(matches[i].lines,lines);
		strcpy(matches[i].oss_lines, oss_lines);
		sprintf(matches[i].matched,"%u%%", matched_percent);
		matches[i].selected = false;
		matches[i].scandata = scan;
	}
	return matches;
}

match_data *load_matches(scan_data *scan, uint8_t *matching_md5)
{
	match_data match;

	/* Compile line ranges */
	char *oss_ranges = malloc(sizeof(match.lines)-1);
	strcpy(oss_ranges, "all");
	char *line_ranges = malloc(sizeof(match.lines)-1);
	strcpy(line_ranges, "all");

	/* Compile match ranges and fill up matched percent */
	int hits = 100;
	int matched_percent = 100;

	if (scan->match_type == snippet)
	{
		scanlog("%d hits before compiling ranges\n", hits);
		hits = compile_ranges(matching_md5, line_ranges, oss_ranges);
		float percent = (hits * 100) / scan->total_lines;
		if (hits) matched_percent = floor(percent);

		scanlog("%d hits left after compiling ranges\n", hits);
		if (!hits)
		{
			free(line_ranges);
			free(oss_ranges);
			return NULL;
		}
	}

	struct match_data *matches = prefill_match(scan, line_ranges, oss_ranges, matched_percent);
	free(oss_ranges);
	free(line_ranges);

	uint32_t records = 0;

	/* Snippet and component match should look for the matching_md5 in components */
	if (scan->match_type != file)
	{
		records = ldb_fetch_recordset(NULL, oss_component, matching_md5, false, handle_component_record, (void *) matches);
		scanlog("Component recordset contains %u records\n", records);
	}

	if (!records)
	{
		records = ldb_fetch_recordset(NULL, oss_file, matching_md5, false, handle_file_record, (void *) matches);
		scanlog("File recordset contains %u records\n", records);
	}

	if (records) return matches;

	if (matches) free(matches);

	scanlog("Match type is 'none' after loading matches\n");
	return NULL;
}

/* Set map hits to zero for the given match */
void clear_hits(uint8_t *match)
{
	match[MD5_LEN] = 0;
	match[MD5_LEN + 1] = 0;
}

/* Check if the provided file id (md5) is orphan */
bool orphan_file(uint8_t *fid)
{
	if (ldb_key_exists(oss_component, fid)) return false;
	if (ldb_key_exists(oss_file, fid)) return false;
	scanlog("Orphan MD5\n");
	return true;
}

/* If we have snippet matches, select the one with more hits */
uint8_t *biggest_snippet(uint8_t *matchmap, uint64_t matchmap_ptr)
{
	uint8_t *out = NULL;
	int hits = 0;

	while (true)
	{
		int most_hits = 0;

		/* Select biggest snippet */
		for (int i = 0; i < matchmap_ptr; i++) {
			hits = uint16_read (matchmap + i * MAP_REC_LEN + MD5_LEN);
			if (hits >= most_hits) {
				most_hits = hits;
				out = matchmap + i * MAP_REC_LEN;
			}
		}

		if (!hits) break;

		/* Erase match from map if MD5 is orphan */
		if (orphan_file(out)) clear_hits(out); else break;
	}
	return out;
}

match_data *compile_matches(scan_data *scan)
{
	uint8_t *matching_md5 = scan->md5;

	/* Search for biggest snippet */
	if (scan->match_type == snippet)
	{
		matching_md5 = biggest_snippet(scan->matchmap, scan->matchmap_ptr);
		scanlog("%ld matches in snippet map\n", scan->matchmap_ptr);
	}

	/* Return NULL if no matches */
	if (!matching_md5)
	{
		scan->match_type = none;
		scanlog("No matching file id\n");
		return NULL;
	}
	else
	{
		/* Log matching MD5 */
		for (int i = 0; i < MD5_LEN; i++) scanlog("%02x", matching_md5[i]);
		scanlog(" selected\n");
	}

	/* Dump match map */
	if (debug_on) map_dump(scan->matchmap, scan->matchmap_ptr);

	/* Gather and load match metadata */
	match_data *matches = NULL;

	scanlog("Starting match: %s\n",matchtypes[scan->match_type]);
	if (scan->match_type != none) matches = load_matches(scan, matching_md5);

	/* The latter could result in no matches */
	if (!matches) scan->match_type = none;
	scanlog("Final match: %s\n",matchtypes[scan->match_type]);

	return matches;
}

/* Scans a wfp file with winnowing fingerprints */
int wfp_scan(char *path)
{
	char * line = NULL;
	size_t len = 0;
	ssize_t lineln;
	uint8_t *rec = calloc(LDB_MAX_REC_LN, 1);

	scan_data scan = scan_data_init();
	scan.preload = true;

	/* Open WFP file */
	FILE *fp = fopen(path, "r");
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
		if ((is_component || is_file) && read_data) ldb_scan(&scan);

		/* Parse file information with format: file=MD5(32),file_size,file_path */
		if (is_file)
		{

			scan_data_reset(&scan);

			const int tagln = 5; // len of 'file='

			/* Get file MD5 */
			char *hexmd5 = calloc(MD5_LEN * 2 + 1, 1);
			memcpy(hexmd5, line + tagln, MD5_LEN * 2);
			hex_to_bin(hexmd5, MD5_LEN * 2, scan.md5);
			free(hexmd5);

			/* Extract fields from file record */
			strcpy((char *)rec, line + tagln + (MD5_LEN * 2) + 1);
			extract_csv(scan.file_size, (char *)rec, 1, LDB_MAX_REC_LN);
			extract_csv(scan.file_path, (char *)rec, 2, LDB_MAX_REC_LN);

			read_data = true;
		}

		/* Save hash/es to memory. Parse file information with format:
		   linenr=wfp(6)[,wfp(6)]+ */

		if (is_wfp && (scan.hash_count < MAX_HASHES_READ))
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
				hex_to_bin(hexhash, 8, (uint8_t *)&scan.hashes[scan.hash_count]);
				uint32_reverse((uint8_t *)&scan.hashes[scan.hash_count]);

				/* Save line number */
				scan.lines[scan.hash_count] = line_nr;

				/* Move pointer to the next hash */
				hexhash += strlen(hexhash) + 1;

				scan.hash_count++;
			}
		}
	}

	/* Scan the last file */
	if (read_data) ldb_scan(&scan);

	fclose(fp);
	if (line) free(line);
	free(rec);

	scan_data_free(scan);
	return EXIT_SUCCESS;
}

bool skip_snippets(char *src, uint64_t srcln)
{
	if (srcln > SKIP_SNIPPETS_IF_FILE_BIGGER) return true;
	if (srcln != strlen(src)) return true; // is binary

	if (!memcmp(src, "{", 1)) return true;     // is json
	if (!memcmp(src, "<?xml", 5)) return true; // is xml
	if (!memcmp(src, "<?XML", 5)) return true; // is xml
	if (!memcmp(src, "<html", 5)) return true; // is html
	if (!memcmp(src, "<HTML", 5)) return true; // is html

	return false;
}

/* Scans a file and returns JSON matches via STDOUT
   scan structure can be already preloaded (.wfp scan)
   otherwise, it will be loaded here (scanning a physical file) */
bool ldb_scan(scan_data *scan)
{
	bool skip = false;

	scan->matchmap_ptr = 0;
	scan->match_type = none;
	scan->timer = microseconds_now();

	/* Get file length */
	uint64_t file_size;
	if (scan->preload) file_size = atoi(scan->file_size);
	else file_size = get_file_size(scan->file_path);

	/* Error reading file */
	if (file_size < 0) ldb_error("Cannot access file");

	/* Calculate MD5 hash (if not already preloaded) */
	if (!scan->preload) file_md5(scan->file_path, scan->md5);

	if (!scan->preload) if (blacklisted(scan->file_path)) skip = true;

	/* Ignore <=1 byte */
	if (file_size <= 1) skip = true;

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
	int total_matches = count_matches(matches);

	/* Debug match info */
	scanlog("%d matches compiled\n", total_matches);
	if (debug_on) for (int i = 0; i < total_matches; i++)
		scanlog("%d, %s\n", matches[i].path_ln, matches[i].file);

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
	if (scan->match_type != none) post_scan(matches);

	/* Output matches */
	scanlog("Match output starts\n");
	output_matches_json(matches, scan);

	if (matches) free(matches);
	return true;
}
