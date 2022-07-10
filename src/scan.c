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

#include "debug.h"
#include "file.h"
#include "ignorelist.h"
#include "ldb.h"
#include "limits.h"
#include "match.h"
#include "parse.h"
#include "query.h"
#include "rank.h"
#include "scan.h"
#include "snippets.h"
#include "util.h"
#include "versions.h"
#include "winnowing.h"
#include "hpsm.h"
#include "match_list.h"

/**
  @file scan.c
  @date 12 Jul 2020
  @brief Scan-related subroutines.
 
  Long description // TODO
  @see https://github.com/scanoss/engine/blob/master/src/scan.c
 */

char *ignored_assets = NULL;

/** @brief Calculate and write source wfp md5 in scan->source_md5 
    @param scan Scan data
	*/
static void calc_wfp_md5(scan_data_t *scan, char * target)
{
	uint8_t tmp_md5[16];
	get_file_md5(target, tmp_md5);
	char *tmp_md5_hex = md5_hex(tmp_md5);
	strcpy(scan->source_md5, tmp_md5_hex);
	free(tmp_md5_hex);
}

/** @brief Init scan structure 
    @param target File to scan
    @return Scan data
    */
scan_data_t * scan_data_init(char *target, int max_snippets, int max_components)
{
	scanlog("Scan Init\n");
	scan_data_t * scan = calloc(1, sizeof(*scan));
	scan->file_path = strdup(target);
	scan->file_size = malloc(MAX_FILE_SIZE);
	scan->hashes = malloc(MAX_FILE_SIZE);
	scan->lines  = malloc(MAX_FILE_SIZE);
	scan->matchmap = calloc(MAX_FILES, sizeof(matchmap_entry));
	scan->match_type = MATCH_NONE;
	*scan->snippet_ids = 0;
	match_list_init(&scan->matches);
	scan->matches.scan_ref = scan;
	scan->max_components_to_process = max_components;
	scan->max_snippets_to_process = max_snippets;

	if (max_snippets)
		scan->matches.max_items = max_snippets;
	else
		scan->matches.max_items = 1;
	
	scan->matches.autolimit = true;

	/* Get wfp MD5 hash */
	if (extension(target)) if (!strcmp(extension(target), "wfp")) calc_wfp_md5(scan, target);

	return scan;
}

/** @brief Frees scan data memory
    @param scan Scan data
	*/
void scan_data_free(scan_data_t * scan)
{
	free(scan->file_path);
	free(scan->file_size);
	free(scan->hashes);
	free(scan->lines);
	free(scan->matchmap);
	match_list_destroy(&scan->matches);
	free(scan);
	scan = NULL;
}

/** @brief Returns true if md5 is the md5sum for NULL
    @param md5 File ID (md5)
    @result Empty file result
	  */
static bool zero_bytes (uint8_t *md5)
{
	uint8_t empty[] = "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e";

	for (int i = 0; i < 15; i++)
		if (md5[i] != empty[i]) return false;

	return true;
}

/** @brief Performs component and file comparison 
    @param fid File ID (md5)
    @return Match type
	  */
static matchtype ldb_scan_file(uint8_t *fid) {
			
	scanlog("Checking entire file\n");
	
	if (zero_bytes(fid)) return none;
	
	matchtype match_type = none;

	if (ldb_key_exists(oss_url, fid)) match_type = url;
	else if (ldb_key_exists(oss_file, fid)) match_type = file;

	return match_type;
}

/** @brief Return true if asset is found in declared_components (-s parameter)
    @param match Match data
    @return Asset declaration result
    */
bool asset_declared(component_data_t * comp)
{
	if (!declared_components) return false;

	/* Travel declared_components */
	for (int i = 0; i < MAX_SBOM_ITEMS; i++)
	{
		char *vendor = declared_components[i].vendor;
		char *component = declared_components[i].component;
		char *purl = declared_components[i].purl;

		/* Exit if reached the end */
		if (!*component && !*vendor && !*purl) break;

		/* Compare purl */
		if (comp->purls[0])
		{
			if (!strcmp((const char *) comp->purls[0], (const char *) purl)) return true;
		}

		/* Compare vendor and component */
		else if (comp->vendor && comp->component)
		{
			if (!strcmp(vendor, comp->vendor) && !strcmp(component, comp->component)) return true;
		}
	}
	return false;
}


/** @brief Scans a file hash only
    @param scan Scan data
    @return Scan result (SUCCESS/FAILURE)
	*/
int hash_scan(char *path, int scan_max_snippets, int scan_max_components)
{
	scan_data_t * scan = scan_data_init(path, scan_max_snippets, scan_max_components);
	scan->preload = true;

		/* Get file MD5 */
	ldb_hex_to_bin(scan->file_path, MD5_LEN * 2, scan->md5);

	/* Fake file length */
	strcpy(scan->file_size, "999");

	/* Scan the last file */
	ldb_scan(scan);

	return EXIT_SUCCESS;
}

/** @brief Scans a wfp file with winnowing fingerprints 
    @param scan Scan data
    @return Scan result (SUCCESS/FAILURE)
	*/
int wfp_scan(char * path, int scan_max_snippets, int scan_max_components)
{
	scan_data_t * scan = NULL;
	char * line = NULL;
	size_t len = 0;
	ssize_t lineln;
	uint8_t *rec = NULL;

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

		bool is_file = (memcmp(line, "file=", 5) == 0);
		bool is_hpsm = (memcmp(line, "hpsm=", 5) == 0);
		bool is_wfp = (!is_file && !is_hpsm);

		if (is_hpsm) 
		{
			hpsm_enabled = hpsm_lib_load();
			hpsm_crc_lines = strdup(&line[5]);
		}

		/* Parse file information with format: file=MD5(32),file_size,file_path */
		if (is_file)
		{
			if (scan)
				ldb_scan(scan);

			const int tagln = 5; // len of 'file='

			/* Get file MD5 */
			//char *hexmd5 = calloc(MD5_LEN * 2 + 1, 1);
			char * hexmd5 = strndup(line + tagln, MD5_LEN * 2);

			/* Extract fields from file record */
			calloc(LDB_MAX_REC_LN, 1);  
			//strcpy((char *)rec, line + tagln + (MD5_LEN * 2) + 1);
			rec = strdup(line + tagln + (MD5_LEN * 2) + 1);
		
			scan = scan_data_init(field_n(2, (char *)rec), scan_max_snippets, scan_max_components);
			extract_csv(scan->file_size, (char *)rec, 1, LDB_MAX_REC_LN);
			scan->preload = true;
			free(rec);
			ldb_hex_to_bin(hexmd5, MD5_LEN * 2, scan->md5);
			free(hexmd5);
		}

		/* Save hash/es to memory. Parse file information with format:
			 linenr=wfp(6)[,wfp(6)]+ */

		if (is_wfp && scan && (scan->hash_count < MAX_HASHES_READ))
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
	ldb_scan(scan);

	fclose(fp);
	if (line) free(line);

	return EXIT_SUCCESS;
}

/** @brief Scans a file and returns JSON matches via STDOUT
   scan structure can be already preloaded (.wfp scan)
   otherwise, it will be loaded here (scanning a physical file) 
   @param scan //TODO
   */
void ldb_scan(scan_data_t * scan)
{
	bool skip = false;
	if (!scan)
		return;

	if (unwanted_path(scan->file_path)) skip = true;

	scan->matchmap_size = 0;
	scan->match_type = none;
	scan->timer = microseconds_now();

	/* Get file length */
	uint64_t file_size;
	if (!skip)
	{
		if (scan->preload) file_size = atoi(scan->file_size);
		else file_size = get_file_size(scan->file_path);
		if (file_size < 0) ldb_error("Cannot access file");
	}

	/* Calculate MD5 hash (if not already preloaded) */
	if (!skip) if (!scan->preload) get_file_md5(scan->file_path, scan->md5);

	if (!skip) if (extension(scan->file_path))
		if (ignored_extension(scan->file_path)) skip = true;

	/* Ignore <=1 byte */
	if (file_size <= MIN_FILE_SIZE) skip = true;

	if (!skip)
	{
		/* Scan full file */
		char *tmp_md5_hex = md5_hex(scan->md5);
		strcpy(scan->source_md5, tmp_md5_hex);
		free(tmp_md5_hex);
	
		scan->match_type = ldb_scan_file(scan->md5);
		

		/* If no match, scan snippets */
		if (scan->match_type == MATCH_NONE)
		{
			/* Load snippets into scan data */
			if (!scan->preload)
			{
				/* Read file into memory */
				char *src = calloc(MAX_FILE_SIZE, 1);
				if (file_size < MAX_FILE_SIZE) read_file(src, scan->file_path, 0);
				
				if(hpsm_enabled) 
				{
					char *aux = hpsm_hash_file_contents(src);
					if(aux)
					{
						hpsm_crc_lines = strdup(&aux[5]);
						free(aux);
					}
				}					
				/* Determine if file is to skip snippet search */
				if (!skip_snippets(src, file_size))
				{	/* Load wfps into scan structure */
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
	compile_matches(scan);
	//match_list_print(matches);
	
	if (scan->matches.headp.lh_first && scan->match_type != MATCH_NONE)
	{
		/* Debug match info */
	//	scanlog("%d matches compiled:\n", total_matches);
	//	if (debug_on) for (int i = 0; i < total_matches; i++)
	//		scanlog("#%d %s, %s\n",i,  matches[i].purl, matches[i].file);

		/* Matched asset in SBOM.json? */
		// for (int i = 0; i < total_matches; i++)
		// {
		// 	if (asset_declared(matches[i]))
		// 	{
		// 		scanlog("Asset matched\n");
		// 		if (engine_flags & ENABLE_REPORT_IDENTIFIED)
		// 		{
		// 			scan->identified = true;
		// 		}
		// 		else
		// 		{
		// 			if (matches) free(matches);
		// 			matches = NULL;
		// 			scan->match_type = none;
		// 		}
		// 		break;
		// 	}
		// }
		

		/* Perform post scan intelligence */
		// if (scan->match_type != none)
		// {
		// 	scanlog("Starting post-scan analysis\n");
		// 	post_scan(matches);
		// }
	}

	/* Output matches */
	scanlog("Match output starts\n");
	output_matches_json(scan);

	//if (matches) free(matches);
	scan_data_free(scan);
}
