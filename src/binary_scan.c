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
  * @file binary_scan.c
  * @date 04 Sep 2022
  * @brief Contains the functions related wiht components

  * EXPERIMENTAL!!! Used to look for binary matches using a "bfp (Binary FInger Print". The client to generate this "bfp" is still being developed
  * @see https://github.com/scanoss/engine/blob/master/src/match.c
  */
#include "match_list.h" 
#include "debug.h"
#include "snippets.h"
#include "scanoss.h"
#include "file.h"
#include "util.h"
#include "match.h"
#include "url.h"
#include "decrypt.h"
#include "report.h"

component_data_t comp_max_hits = {.hits=-1};
static bool component_hits_comparation(component_data_t *a, component_data_t *b)
{
	if (!strcmp(a->purls[0], b->purls[0]))
	{
		a->hits++;
		return true;;
	}
	return false;
}

static bool sort_by_hits(component_data_t *a, component_data_t *b)
{
	if (b->hits > a->hits)
	{
		return true;;
	}

	return false;
}

#define MAX_URLS 100

static bool add_purl_from_urlid(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{

	if (iteration > MAX_URLS)
		return true;
	/* Ignore path lengths over the limit */
	if (!datalen || datalen >= (MD5_LEN + MAX_FILE_PATH)) return false;

	/* Decrypt data */
	char * decrypted = decrypt_data(raw_data, datalen, oss_file, key, subkey);
	if (!decrypted)
		return NULL;
	
	component_list_t * component_list = (component_list_t*) ptr;
	/* Copy data to memory */
	uint8_t url_id[MD5_LEN];
	memcpy(url_id, raw_data, MD5_LEN);
	char path[MAX_FILE_PATH+1];
	strncpy(path, decrypted, MAX_FILE_PATH);

	uint8_t *url_rec = calloc(LDB_MAX_REC_LN, 1); /*Alloc memory for url records */
	ldb_fetch_recordset(NULL, oss_url, url_id, false, get_oldest_url, (void *)url_rec);

	/* Create a new component and fill it from the url record */
	component_data_t *new_comp = calloc(1, sizeof(*new_comp));
	bool result = fill_component(new_comp, url_id, path, (uint8_t *)url_rec);
	if (result)
	{	
		//new_comp->file_md5_ref = component_list->match_ref->file_md5;
		if (!component_list_add_binary(component_list, new_comp, component_hits_comparation, true))
		{
			scanlog("Purl found %s, hits:%d\n",new_comp->purls[0], new_comp->hits);
			if (new_comp->hits > comp_max_hits.hits)
			{
				memcpy(&comp_max_hits, new_comp, sizeof(component_data_t));
				printf("<<NEW MAX %s - %d>>\n", comp_max_hits.purls[0], comp_max_hits.hits);
			}
			component_data_free(new_comp); /* Free if the componet was rejected */
		}
		scanlog("<list size: %d>\n", component_list->items);
	}
	else
	{
		scanlog("incomplete component: %s\n", new_comp->component);
		component_data_free(new_comp);
	}
	
	free(url_rec);
	free(decrypted);
	
	//scanlog("#%d File %s\n", iteration, files[iteration].path);
	return false;
}


int max_files_to_process = 4;
/**
 * @brief Handler function to collect all file ids.
 * Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr //TODO
 * @return //TODO
 */
static bool get_all_file_ids(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	//component_list_t * comp_list = (component_list_t *) ptr;
	file_recordset * files = (file_recordset *) ptr;
	if (datalen)
	{
		if (iteration < max_files_to_process * 2)
		{
			memcpy(files[iteration].url_id, data, MD5_LEN);
			return false;
		} 
		return true;
		//uint32_t size = uint32_read(record);

		/* End recordset fetch if MAX_QUERY_RESPONSE is reached */
		//if (size + datalen + 4 >= MAX_QUERY_RESPONSE) return true;

		/* End recordset fetch if MAX_FILES are reached for the snippet */
		//if ((WFP_REC_LN * matchmap_max_files) <= (size + datalen)) return true;

		/* Save data and update dataln */
		//memcpy(record + size + 4, data, datalen);
		//uint32_write(record, size + datalen);

	}
	
	return false;
}



/**
 * @brief Performs a wfp scan.
 * Files with wfp extension will be scanned in this mode. 
 * Remember: wfp = Winnowings Finger Print.
 * This file could be generated with a client.
 * @param path wfp file path
 * @param scan_max_snippets Limit for matches list. Autolimited be default.
 * @param scan_max_components Limit for component to be displayed. 1 by default.
 * @return EXIT_SUCCESS
 */
static component_list_t *  binary_scan_run(char * path, int sensibility)
{
	struct ldb_table oss_fhash = {.db = "oss", .table = "fhashes", .key_ln = 16, .rec_ln = 0, .ts_ln = 2, .tmp = false};
	char * line = NULL;
	size_t len = 0;
	ssize_t lineln;
    int hash_count = 0;
	/* Open WFP file */
	FILE *fp = fopen(path, "r");
	if (fp == NULL)
	{
		fprintf(stdout, "E017 Cannot open target");
		return NULL;
	}

	if (sensibility > 0)
		max_files_to_process = sensibility;
	scanlog("<<< Binary scan: %d>>>>\n", max_files_to_process);
	/* Get wfp MD5 hash */
	uint8_t tmp_md5[16];
	get_file_md5(path, tmp_md5);
	char *tmp_md5_hex = md5_hex(tmp_md5);
	uint8_t *md5_set = calloc(1, MAX_QUERY_RESPONSE);

	/*Init a new scan object for the next file to be scanned */
	component_list_t * comp_list = calloc(1, sizeof(component_list_t));
	component_list_init(comp_list, 0);
	/* Read line by line */
	while ((lineln = getline(&line, &len, fp)) != -1)
	{
		trim(line);

		bool is_file = (memcmp(line, "file=", 5) == 0);

		/* Parse file information with format: file=MD5(32),file_size,file_path */
		if (is_file)
		{
			// /* A scan data was fullfilled and is ready to be scanned */
			// if (scan)
			// 	ldb_scan(scan);
			
			// /* Prepare the next scan */
			// const int tagln = 5; // len of 'file='

			// /* Get file MD5 */
			// char * hexmd5 = strndup(line + tagln, MD5_LEN * 2);

			// /* Extract fields from file record */
			// calloc(LDB_MAX_REC_LN, 1);  
			
			// rec = (uint8_t*) strdup(line + tagln + (MD5_LEN * 2) + 1);
			// char * target = field_n(2, (char *)rec);
			
			// /*Init a new scan object for the next file to be scanned */
			// scan = scan_data_init(target, scan_max_snippets, scan_max_components);
			// strcpy(scan->source_md5, tmp_md5_hex);
			// extract_csv(scan->file_size, (char *)rec, 1, LDB_MAX_REC_LN);
			// scan->preload = true;
			// free(rec);
			// ldb_hex_to_bin(hexmd5, MD5_LEN * 2, scan->md5);
			// free(hexmd5);
		} 

		else 
		{
			//scanlog("Processing FHASH: %s\n", line);
			/* Convert hash to binary */
			uint8_t fhash[16]; 
			ldb_hex_to_bin(line, 32, fhash);
			hash_count++;
			/* Get all file IDs for given wfp */
			uint32_write(md5_set, 0);
			file_recordset *files = calloc(1001, sizeof(file_recordset));;
			int records = ldb_fetch_recordset(NULL, oss_fhash, fhash, false, get_all_file_ids, (void *) files);
			if (records < max_files_to_process)
			{
				for (int i = 0; i < records; i++)
				{
					ldb_fetch_recordset(NULL, oss_file, files[i].url_id, false, add_purl_from_urlid,(void *)comp_list);
				}
			}
			free(files);
			/* md5_set starts with a 32-bit item count, followed by all 16-byte records */
			//uint32_t md5s_ln = uint32_read(md5_set);
			//uint8_t *md5s = md5_set + 4;

			//	scanlog("Snippet %02x%02x%02x%02x (line %d) -> %u hits %s\n", wfp[0], wfp[1], wfp[2], wfp[3], line, md5s_ln / WFP_REC_LN, traced ? "*" : "");
			//if (md5s_ln && md5s_ln < 10000)
			//	add_files_to_matchmap(scan, md5s, md5s_ln, fhash);
		}
		printf("\n----------------------%s-------------------------\n", line);
	}
	free(md5_set);
	fclose(fp);
	if (line) free(line);

	free(tmp_md5_hex);	
	
	//compile_matches(scan);
	scanlog("Match output starts\n");
	//output_matches_json(scan);

	//if (matches) free(matches);
	return comp_list;
}

int binary_scan(char * path)
{
	component_list_t * result = NULL;
	int sensibility = 1;
	while (sensibility < 100)
	{
		result = binary_scan_run(path, sensibility);
		if (!result)
			return -1;
		if (result->items > 1)
			break;
		component_list_destroy(result);
		sensibility++;
	};

	component_list_t * comp_list_sorted = calloc(1, sizeof(component_list_t));
	component_list_init(comp_list_sorted, 10);
	struct comp_entry *item = NULL;
	LIST_FOREACH(item, &result->headp, entries)
	{
		component_list_add(comp_list_sorted,item->component, sort_by_hits, false);
	}
	
	item = NULL;
	LIST_FOREACH(item, &comp_list_sorted->headp, entries)
	{
		printf("%s - %d\n",item->component->purls[0], item->component->hits);
	}

	component_list_destroy(result);
	free(comp_list_sorted);

	return 0;
	
}