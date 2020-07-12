// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/scan.c
 *
 * Scan-related subroutines
 *
 * Copyright (C) 2018-2020 SCANOSS LTD
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
matchtype ldb_scan_file(uint8_t *fid, long *elapsed) {
			
	scanlog("Checking entire file\n");
	
	if (zero_bytes(fid)) return none;
	
	/* Stopwatch starts */
	struct timeval start; gettimeofday(&start, NULL);

	matchtype match_type = none;

	if (ldb_key_exists(oss_component, fid)) match_type = component;
	else if (ldb_key_exists(oss_file, fid)) match_type = file;

	/* Stopwatch stops */
	*elapsed = elapsed_time(start);

	return match_type;

}

void adjust_tolerance(uint32_t wfpcount)
{

	/* Range tolerance is the maximum amount of non-matched lines accepted
		within a matched range. This goes from 15 in small files to 5 in large files */

	range_tolerance = 15 - floor(wfpcount / 20);
	if (range_tolerance < 5) range_tolerance = 5;

	/* Min matched lines is the number of matched lines in total under which the result
       is ignored. This goes from 3 in small files to 10 in large files */


	min_match_lines = 3 + floor(wfpcount / 5);
	if (min_match_lines > 10) min_match_lines = 10;

	scanlog("Tolerance: range=%d, lines=%d\n", range_tolerance, min_match_lines);

}

/* Handler function to collect all file ids */
bool get_all_file_ids(uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
    uint8_t *record = (uint8_t *) ptr;

    if (datalen)
    {
		/* Save data and update dataln */
		uint32_t size = uint32_read(record);
		memcpy(record + size + 4, data, datalen);
        uint32_write(record, size + datalen);
 	}
	return false;
}

/* Query all wfp and add resulting file ids to the matchmap
   matchmap is a series of fixed-length records with the following structure:
   [MD5(16)][hits(2)][range1(4)]....[rangeN(4)][lastwfp(4)] */

matchtype ldb_scan_snippets(uint8_t *matchmap, uint64_t *matchmap_ptr, uint32_t *wfps, uint32_t wfpcount, uint32_t* lines, long *elapsed) {

	if (!wfpcount) return none;

	scanlog("Checking snippets\n");

	adjust_tolerance(wfpcount);

	/* Stopwatch starts */
	struct timeval start; gettimeofday(&start, NULL);

	uint32_t line = 0;
	uint32_t prev_line = 1;
	uint8_t *md5 = calloc (19, 1);
	uint8_t *wfp_ptr;
	uint8_t wfp[4];
	uint32_t from = 0;
	uint32_t to = 0;

	uint8_t *all_md5 = malloc(max_query_response);
	uint32_t all_md5_ln = 0;
	uint16_t hits = 0;
	int consecutive = 0;

	/* Limit snippets to be scanned  */
	if (wfpcount > max_snippets_scanned) wfpcount = max_snippets_scanned;

	/* Compare each wfp */
	for (long i = 0; i < wfpcount; i++)
	{
		/* Read line number and wfp */
		line = lines[i];
		wfp_ptr = (uint8_t*)&wfps[i];
		wfp[0]=wfp_ptr[3];
		wfp[1]=wfp_ptr[2];
		wfp[2]=wfp_ptr[1];
		wfp[3]=wfp_ptr[0];

		/* Get all file IDs for given wfp */
		uint32_write(all_md5, 0);
		ldb_fetch_recordset(oss_wfp, wfp, get_all_file_ids, (void *) all_md5);
		all_md5_ln = uint32_read(all_md5);
		uint8_t *md5_records = all_md5 + 4;

		if (all_md5_ln > (wfp_popularity_threshold*18)) all_md5_ln = 0;

		/* If a snippet brings more than "score" result by "hits" times in a row, we skip "jump" snippets */
		if (all_md5_ln > consecutive_score) 
		{
			if (++consecutive >= consecutive_hits) 
			{
				i += consecutive_jump;
				consecutive = 0;
			}
		}

		/* Recurse each record from the wfp table */
		for (int n = 0; n < all_md5_ln; n += 18)
		{
			/* Retrieve an MD5 from the recordset */
			memcpy (md5, md5_records + n, 16);

			/* The md5 is followed by the line number where the wfp hash was seen */
			uint8_t *oss_line = md5_records + n + 16;

			/* Check if md5 already exists in map */
			long found = -1;
			for (long t=0; t < *matchmap_ptr; t++)
			{
				if (md5cmp(matchmap + t * map_rec_len, md5))
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
				if (*(matchmap_ptr) >= max_files) break;
				memcpy (matchmap + (*matchmap_ptr * map_rec_len), md5, 16);
				found = *matchmap_ptr;
			}

			/* Search for the right range */
			uint32_t record_offset = found * map_rec_len;
			uint32_t ranges_offset = record_offset + 18; // We skip MD5(16) + hits (2)
			hits = uint16_read (matchmap + record_offset + 16);
			to = line;
			uint8_t *lastwfp = matchmap + ranges_offset + 6 * MAX_MAP_RANGES;

			for (uint32_t t = 0; t < MAX_MAP_RANGES; t++)
			{
				from = uint16_read (matchmap + ranges_offset + 6 * t);
				to   = uint16_read (matchmap + ranges_offset + 6 * t + 2);

				/* New range */
				if (from == 0 && to == 0)
				{
					/* Update from and to */
					uint16_write (matchmap + ranges_offset + 6 * t, prev_line);
					uint16_write (matchmap + ranges_offset + 6 * t + 2, line);
					memcpy(matchmap + ranges_offset + 6 * t + 4, oss_line, 2);
					break;
				}

				/* Another hit in the same line, no need to expand range */
				else if (to == line) break;

				/* Increase range */
				else if ((prev_line - to) < range_tolerance)
				{
					/* Update to */
					uint16_write (matchmap + (ranges_offset + 6 * t + 2), line);
					break;
				}
			}

			/* Update hits count (if we are not hitting the same wfp again) */
			if (to != line)
			{	
				if (memcmp(wfp,lastwfp,4)) 
				{
					uint16_write (matchmap + record_offset + 16, (uint16_t) (1 + hits));
					memcpy(lastwfp,wfp,4);
				}
			}

			if (found == *matchmap_ptr) (*matchmap_ptr)++;
		}
		prev_line = line;
	}

	free(all_md5);
	free(md5);

	/* Stopwatch stops */
	*elapsed = elapsed_time(start);
	if ((*matchmap_ptr) > 0) return snippet;
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

	if (uint16_read(matchmap_matching + 16) < 2) return 0;

	int hits = 0;
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

	char *asset = calloc(ldb_max_recln, 1);
	sprintf(asset, "%s,", match.component);

	if (strstr(sbom, asset)) found = true;
	free(asset);

	return found;
}

bool blacklist_match(uint8_t *component_record)
{
	if (!blacklisted_assets) return false;

	bool found = false;	

	char *asset = calloc(ldb_max_recln, 1);
	extract_csv(asset, (char *) component_record, 2, ldb_max_recln);
	strcat(asset, ",");

	if (strcasestr(blacklisted_assets, asset)) found = true;
	free(asset);

	if (found) scanlog("Component blacklisted: %s\n", component_record);

	return found;
}

match_data match_init()
{
	match_data match;
	*match.lines=0;
	*match.vendor=0;        
	*match.component=0;
	*match.version=0;       
	*match.latest_version=0;        
	*match.lines=0;
	*match.oss_lines=0;
	*match.url=0;   
	*match.file=0;  
	*match.matched=0;       
	*match.size=0;
	match.selected = false;
	return match;
}

match_data fill_match(uint8_t *file_record, uint8_t *component_record)
{
	match_data match;
	match.selected = false;

	/* Extract fields from file record */
	if (file_record)
	{
		extract_csv(match.size, (char *) file_record, 1, sizeof(match.size));
		extract_csv(match.file, (char *) file_record, 2, sizeof(match.file));
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

/* Adds match to matches. Returns false if matches are full */		
bool add_match(match_data match, match_data *matches, bool component_match)
{

	/* Verify if metadata is complete */
	if (!*match.vendor || !*match.component || !*match.url || !*match.version || !*match.file || !*match.size)
	{
		scanlog("Metadata is incomplete: %s,%s,%s,%s,%s,%s\n",match.vendor,match.component,match.version,match.size,match.url,match.file);  
		return false;
	}

	/* Check if matched file is a blacklisted extension */
	if (!component_match) if (blacklisted(match.file))
	{
		scanlog("Extension blacklisted for %s\n", match.file);
		return false;
	}

	int n = 0;

	/* Count total number of current matches */
	for (n = 0; n < scan_limit; n++) 
	{
		if (!*matches[n].component) break;
	}

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
		if (n < scan_limit)
		{
			strcpy(matches[n].vendor, match.vendor);
			strcpy(matches[n].component, match.component);
			strcpy(matches[n].version, match.version);
			strcpy(matches[n].latest_version, match.latest_version);
			strcpy(matches[n].url, match.url);
			strcpy(matches[n].file, match.file);
			strcpy(matches[n].size, match.size);
			matches[n].selected = match.selected;
		}

		else
		{ 
			scanlog("Match cannot be added\n");  
			return false;
		}
	}

	return true;
}

bool handle_match_record(uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	if (!datalen) return false;
	data[datalen] = 0;

	/* Skip unwanted paths */
	if (skip_file_path(data, datalen)) return false;

	struct match_data *matches = (struct match_data*) ptr;

	struct match_data match = match_init();

	uint8_t *component = NULL;

	bool component_match = (matches[0].type == 1);

	if (component_match)
	{
		match = fill_match(NULL, data);
	}
	else
	{
		/* If component does not exist (orphan file) skip it */
		if (!ldb_key_exists(oss_component, data)) 
		{
			scanlog("Orphan file\n");
			return false;
		}

		component = calloc(ldb_max_recln, 1);
		get_component_record(data, component);
		if (*component)
		{
			match = fill_match(data + 16, component);
		}
		else scanlog("No component data found\n");
	}

	/* Matched asset in SBOM.json? */
	if (assets_match(match))
	{
		scanlog("Asset matched\n");
		if (component) free(component);
		return true;
	}

	add_match(match, matches, component_match);
	if (component) free(component);

	return false;
}

struct match_data *prefill_match(matchtype match_type, char *lines, char *oss_lines, int matched_percent)
{
	struct match_data *matches = calloc(sizeof(match_data), scan_limit);
	for (int i = 0; i < scan_limit; i++)
	{
		matches[i].type = match_type;
		strcpy(matches[i].lines,lines);
		strcpy(matches[i].oss_lines, oss_lines);
		sprintf(matches[i].matched,"%u%%", matched_percent);
		matches[i].selected = false;
	}
	return matches;
}

match_data *load_matches(uint8_t *matchmap, uint64_t matchmap_ptr, uint8_t *matching_md5, matchtype match_type, uint32_t total_lines)
{
	if (!matching_md5) 
	{
		scanlog("No matching file id\n");
		return NULL;
	}

	match_data match;

	/* Compile line ranges */
	char *oss_ranges = malloc(sizeof(match.lines)-1);
	strcpy(oss_ranges, "all");
	char *line_ranges = malloc(sizeof(match.lines)-1);
	strcpy(line_ranges, "all");

	/* Compile match ranges and fill up matched percent */
	int hits = 100;
	int matched_percent = 100;

	if (match_type == snippet) 
	{
		hits = compile_ranges(matching_md5, line_ranges, oss_ranges);
		float percent = (hits * 100) / total_lines;
		if (hits) matched_percent = floor(percent);
		scanlog("%d hits left after compiling ranges\n", hits);
	}

	if (!hits)
	{
		free(line_ranges);
		free(oss_ranges);
		return NULL;
	}

	struct match_data *matches = prefill_match(match_type, line_ranges, oss_ranges, matched_percent);
	free(oss_ranges);
	free(line_ranges);

	uint8_t *rs = calloc (max_query_response, 1);

	/* Get first record to determine if a file/component was found for the matching_md5 */
	ldb_get_first_record((match_type == component) ? oss_component : oss_file, matching_md5, (void *) rs);

	uint32_t bytes_read = uint32_read(rs);
	uint32_write(rs, 0);
	if (bytes_read) scanlog("Metadata found for matching ID\n");

	uint32_t records;

	/* Snippet matches and no files found? Search straight for a full component */
	if (!bytes_read && match_type == snippet)
	{
		records = ldb_fetch_recordset(oss_component, matching_md5, handle_match_record, (void *) matches);
		scanlog("Searching for direct component match results in %u records\n", records);
	}
	else
	{
		records = ldb_fetch_recordset((match_type == component) ? oss_component : oss_file, matching_md5, handle_match_record, (void *) matches);
	}

	free(rs);

	if (records) return matches;

	if (matches) free(matches);

	scanlog("Match type is 'none' after loading matches\n");
	return NULL;
}

/* If we have snippet matches, select the one with more hits */
uint8_t *biggest_snippet(uint8_t *matchmap, uint64_t matchmap_ptr)
{
	uint8_t *out = NULL;
	int most_hits = 0;
	int hits = 0;
	for (int i = 0; i < matchmap_ptr; i++) {
		hits = uint16_read (matchmap + i * map_rec_len + 16);
		if (hits >= most_hits) {
			most_hits = hits;
			out = matchmap + i * map_rec_len;
		}
	}
	return out;
}

void compile_matches(uint8_t *md5, char *path, uint8_t *matchmap, uint64_t matchmap_ptr, matchtype match_type, uint32_t total_lines, long elapsed) {

	uint8_t *matching_md5 = md5;

	/* Search for biggest snippet */
	if (match_type == snippet)
	{
		matching_md5 = biggest_snippet(matchmap, matchmap_ptr);
		scanlog("%ld matches in snippet map\n", matchmap_ptr);
	}

	/* Dump match map */
	if (debug_on) map_dump(matchmap, matchmap_ptr);

	/* Gather and load match metadata */
	match_data *matches = load_matches(matchmap, matchmap_ptr, matching_md5, match_type, total_lines);

	scanlog("Match type: %s\n", matchtypes[match_type]);

	/* The latter could result in no matches */
	if (!matches) match_type = none;

	/* Perform post scan intelligence */
	if (match_type != none) post_scan(matches);

	output_matches_json(matches, match_type, md5, path, elapsed);

	if (matches) free(matches);

}


/* Scans a wfp file with winnowing fingerprints */
int wfp_scan(char *path)
{
	// Count files
	char * line = NULL;
	size_t len = 0;
	ssize_t lineln;
	FILE * fp;
	fp = fopen (path, "r");
	if (fp == NULL)
	{
		fprintf (stdout, "E017 Cannot open target");
		return EXIT_FAILURE;
	}
	int total_files = 0;
	while ((lineln = getline (&line, &len, fp)) != -1)
		if (!strncmp(line,"file=",5)) total_files++;

	fclose(fp);

	// Scan files
	fp = fopen (path, "r");
	if (fp == NULL)
	{
		fprintf (stdout, "E017 Cannot open target");
		return EXIT_FAILURE;
	}

	uint8_t *md5 = calloc (16,1);
	uint8_t *rec = calloc (ldb_max_recln, 1);
	char *file_path = calloc(ldb_max_recln, 1);
	char *file_size = calloc(ldb_max_recln, 1);

	uint32_t *hashes = malloc(max_file_size);
	uint32_t hashcount = 0;
	uint32_t *lines  = malloc(max_file_size);

	bool skip_snippets = true;
	uint32_t file_counter = 0;
	bool no_match = false;
	bool matches_returned = false;
	long filesize = 0;

	/* Stopwatch starts */
	struct timeval start; gettimeofday(&start, NULL);

	while ((lineln = getline (&line, &len, fp)) != -1)
	{
		trim(line);

		bool is_component = (memcmp(line, "component=", 4) == 0);
		bool is_file = (memcmp(line, "file=", 5) == 0);
		long elapsed = 0;

		/*  We arrive to a file or component and have hashes to scan from the previous file */
		if (is_component || is_file)
		{
			if (hashcount && (filesize < max_file_size))
			{

				/* Scan collected snippets */
				uint8_t *matchmap    = calloc (max_files * map_rec_len, 1);
				uint64_t matchmap_ptr = 0;
				uint32_t total_lines = lines[hashcount - 1];
				matchtype match_type = ldb_scan_snippets(matchmap, &matchmap_ptr, hashes, hashcount, lines, &elapsed);
				hashcount = 0;

				/* Stopwatch stops */
				elapsed = elapsed_time(start);

				/* Compile matches */
				compile_matches(md5, file_path, matchmap, matchmap_ptr, match_type, total_lines, elapsed);
				matches_returned = true;
				free(matchmap);

				/* Stopwatch restarts */
				gettimeofday(&start, NULL);
			}
			else if (file_counter > 0 && !skip_snippets)
			{
				output_matches_json(NULL, 0, md5, file_path, elapsed);
				matches_returned = true;
			}

			if (is_file && matches_returned) matches_returned = true;

			no_match = false;
		} 

		if (is_file)
		{
			skip_snippets = false;

			/* Parse file information */
			char *hexmd5 = calloc(33,1);
			memcpy(hexmd5, line+5, 32);
			hex_to_bin(hexmd5, 32, md5);
			strcpy((char *) rec, line + 5 + 32 + 1);

			/* Extract fields from file record */
			extract_csv(file_size, (char *)rec, 1, ldb_max_recln);
			extract_csv(file_path, (char *)rec, 2, ldb_max_recln);
			filesize = atoi(file_size);
			free(hexmd5);

			matchtype match_type = none;

			long elapsed = 0;
			/* Scan full file */
			if (match_type == none) match_type = ldb_scan_file(md5, &elapsed);

			if (match_type != none)
			{
				/* Stopwatch stops */
				elapsed = elapsed_time(start);

				/* Compile matches */
				compile_matches(md5, file_path, NULL, 0, match_type, 0, elapsed);
				skip_snippets = true;

				/* Stopwatch restarts */
				gettimeofday(&start, NULL);
			}

			else no_match = true;

			if (!no_match) matches_returned = true;

			hashcount = 0;
		}

		/* Save hash to memory */
		else if (!skip_snippets)
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
				hex_to_bin(hexhash, 8, (uint8_t *)&hashes[hashcount]);
				uint32_reverse((uint8_t *)&hashes[hashcount]);

				/* Save line number */
				lines[hashcount++] = line_nr;
				if (hashcount >= 65535)
				{
					skip_snippets = true;
					break;
				}

				/* Move pointer to the next hash */
				hexhash += strlen(hexhash) + 1;
			}
		}
	}

	/* Snippet scan for the last file, if needed */
	long elapsed = 0;
	if (hashcount && *md5) 
	{
		uint8_t *matchmap = calloc(max_files * map_rec_len, 1);
		uint64_t matchmap_ptr = 0;
		uint32_t total_lines = lines[hashcount - 1];
		matchtype match_type = ldb_scan_snippets(matchmap, &matchmap_ptr, hashes, hashcount, lines, &elapsed);

		/* Stopwatch stops */
		elapsed = elapsed_time(start);

		/* Compile matches */
		compile_matches(md5, file_path, matchmap, matchmap_ptr, match_type, total_lines, elapsed);

		free(matchmap);
	}
	else if (file_counter > 0 && !skip_snippets) output_matches_json(NULL, 0, md5, file_path, elapsed);

	fclose(fp);
	if (line) free(line);
	free(md5);
	free(rec);
	free(file_path);
	free(file_size);
	free(hashes);
	free(lines);

	return EXIT_SUCCESS;
}

/* Returns true if the first line of the given src is longer than LONG_LINE_LEN */
bool is_long_line(char *src)
{
	return true;
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

	/* Skip if first line is too long */
	if (srcln < SKIP_SNIPPETS_IF_1ST_LINE_LONGER) return false;
	for (int i = 0; i < SKIP_SNIPPETS_IF_1ST_LINE_LONGER; i++)
		if (src[i] == 10) return false;
	return true;
}

/* Scans a file and returns JSON matches via STDOUT */
bool ldb_scan(char *root_path, char *path)
{

	uint64_t matchmap_ptr = 0;
	matchtype match_type = none;
	char *fullpath = malloc (max_path);
	long elapsed = 0;

	/* Stopwatch starts */
	struct timeval start; gettimeofday(&start, NULL);

	strcpy (fullpath, path);

	/* Check if file is readable and if it is under CFG_MAXFILELEN */
	uint64_t file_len = file_size (fullpath);

	/* Error reading file */
	if (file_len < 0) ldb_error ("Cannot access file");

	/* Initialize matchmap */
	uint8_t *matchmap    = calloc (max_files * map_rec_len, 1);

	/* Calculate MD5 hash */
	uint8_t *md5 = file_md5(fullpath);
	uint32_t total_lines = 0;

	/* Ignore <=1 byte */
	if (file_len > 1)
	{

		/* Scan full file */
		match_type = ldb_scan_file(md5, &elapsed);

		/* If no match, scan snippets */
		if (match_type == none)
		{
			char *src = calloc (max_file_size, 1);

			/* Read file into memory */
			if (file_len < max_file_size) read_file (src, fullpath, 0);

			if (!skip_snippets(src, file_len))
			{
				/* Calculate snippet wfps and scan them */
				uint32_t *wfps = malloc(max_file_size);
				uint32_t *lines  = malloc(max_file_size);
				uint32_t wfpcount = winnowing (src, wfps, lines, max_file_size);

				if (wfpcount)
				{
					match_type = ldb_scan_snippets(matchmap, &matchmap_ptr, wfps, wfpcount, lines, &elapsed);
					total_lines = lines[wfpcount - 1];
				}

				free(wfps);
				free(lines);
			}
			else scanlog("File skipped\n");

			free(src);
		}
	}

	/* Stopwatch stops */
	elapsed = elapsed_time(start);

	compile_matches(md5, fullpath, matchmap, matchmap_ptr, match_type, total_lines, elapsed);

	free (md5);
	free (matchmap);
	free (fullpath);

	return true;
}
