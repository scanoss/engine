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
#include "ignorelist.h"
#include "winnowing.h"
#include "ldb.h"
#include "versions.h"

char *sbom = NULL;
char *ignored_assets = NULL;

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

	if (ldb_key_exists(oss_url, fid)) match_type = url;
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

/* Determine if a file is to be skipped based on extension or path content */
bool skip_file_path(char *path, match_data *matches)
{
	bool unwanted = false;

	/* Skip unwanted path */
	if (unwanted_path(path)) unwanted = true;

	/* Skip ignored extension */
	else if (extension(path) && ignored_extension(path))
	{
		scanlog("Ignored extension\n");
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

	/* Check if matched file is a ignored extension */
	if (extension(path))
	{
		if (ignored_extension(path))
		{
			scanlog("Ignored extension\n");
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
		if (ignored_extension(scan->file_path)) skip = true;

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
