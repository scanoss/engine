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
	if (!datalen || datalen >= (oss_file.key_ln + MAX_FILE_PATH)) return false;

	/* Decrypt data */
	char * decrypted = decrypt_data(raw_data, datalen, oss_file, key, subkey);
	if (!decrypted)
		return NULL;
	
	component_list_t * component_list = (component_list_t*) ptr;
	/* Copy data to memory */
	uint8_t url_id[oss_url.key_ln];
	memcpy(url_id, raw_data, oss_url.key_ln);
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
				scanlog("<<NEW MAX %s - %d>>\n", comp_max_hits.purls[0], comp_max_hits.hits);
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
			memcpy(files[iteration].url_id, data, oss_url.key_ln);
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

static void fhash_process(char * hash, component_list_t * comp_list)
{
	struct ldb_table oss_fhash = {.db = "oss", .table = "fhashes", .key_ln = 16, .rec_ln = 0, .ts_ln = 2, .tmp = false, .keys=2, .definitions = 0};
	
	if (!ldb_table_exists(oss_fhash.db, oss_fhash.table)) // skip if the table is not present
		return;
	
	uint8_t fhash[16]; 
	ldb_hex_to_bin(hash, 32, fhash);
	/* Get all file IDs for given wfp */
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
}


typedef struct binary_match_t
{
	char * file;
	char * md5;
	component_list_t * components;
} binary_match_t;

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
static binary_match_t  binary_scan_run(char * bfp, int sensibility)
{
	
//	char * line = NULL;
	//size_t len = 0;
	//ssize_t lineln;
   // int hash_count = 0;
	binary_match_t result = {NULL, NULL, NULL};

	if (sensibility > 0)
		max_files_to_process = sensibility;
	scanlog("<<< Binary scan: %d>>>>\n", max_files_to_process);


	/*Init a new scan object for the next file to be scanned */
	result.components = calloc(1, sizeof(component_list_t));
	component_list_init(result.components, 0);
	
	const char s[2] = ",";
	char *token;
   /* get the first token */
	token = strtok(bfp, s);
	int field = 0;
   /* walk through other tokens */
   while( token != NULL ) 
   {
      if (field == 0)
	  {
		result.md5 = strdup(token);
	  }
	  else if (field == 1)
	  {
		
	  }
	  else if (field == 2)
	  {
		result.file = strdup(token);
	  }
	  else
	  {
		fhash_process(token, result.components);
	  }

	  field++;
	//printf( "%d - %s\n", field, token );
    
    token = strtok(NULL, s);
   }

	return result;
}

extern bool first_file;
int binary_scan(char * input)
{
	/* Get file MD5 */
	char * hexmd5 = strndup(input, oss_file.key_ln * 2);
	scanlog("Bin File md5 to be scanned: %s\n", hexmd5);
	uint8_t bin_md5[oss_file.key_ln];
	ldb_hex_to_bin(hexmd5, oss_file.key_ln * 2, bin_md5);
	free(hexmd5);

	/*uint8_t zero_md5[oss_file.key_ln] = {0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e}; //empty string md5
	
	if (!memcmp(zero_md5,bin_md5, MD5_LEN)) //the md5 key of an empty string must be skipped.
		return -1;*/
	
	if (ldb_key_exists(oss_file, bin_md5))
	{
		scanlog("bin file md5 match\n");
		char  * file_name = field_n(3,input);
		int target_len = strchr(file_name,',') - file_name;
		char * target = strndup(file_name, target_len);
		scan_data_t * scan =  scan_data_init(target, 1, 1);
		free(target);
		memcpy(scan->md5, bin_md5, oss_file.key_ln);
		scan->match_type = MATCH_FILE;
		compile_matches(scan);

		if (scan->best_match)
		{
			scanlog("Match output starts\n");
			if (!quiet)
				output_matches_json(scan);
			
			scan_data_free(scan);
			return 0;
		}
		else
		{
			scanlog("No best match, scanning binary\n");
		}

		scan_data_free(scan);
	}
	
	binary_match_t result = {NULL, NULL, NULL};
	int sensibility = 1;
	while (sensibility < 100)
	{
		char * bfp = strdup(input);
		result = binary_scan_run(bfp, sensibility);
		free(bfp);
		if (!result.components)
			return -1;
		if (result.components->items > 1 && result.components->headp.lh_first->component->hits > 0)
			break;
		component_list_destroy(result.components);
		free(result.file);
		result.file = NULL;
		free(result.md5);
		result.md5 = NULL;
		
		sensibility++;
	};

	component_list_t * comp_list_sorted = calloc(1, sizeof(component_list_t));
	component_list_init(comp_list_sorted, 10);
	struct comp_entry *item = NULL;
	LIST_FOREACH(item, &result.components->headp, entries)
	{
		component_list_add(comp_list_sorted,item->component, sort_by_hits, false);
	}
	
	if (!quiet)
		if (!first_file)
			printf(",");
	first_file = false;
	item = NULL;
	printf("\"%s\":{\"hash\":\"%s\",\"id\":\"bin_snippet\",\"matched\":[", result.file, result.md5);
	LIST_FOREACH(item, &comp_list_sorted->headp, entries)
	{
		printf("{\"purl\":\"%s\", \"hits\": %d}",item->component->purls[0], item->component->hits);
		if (item->entries.le_next)
			printf(",");
	}
	printf("]}");
	component_list_destroy(result.components);
	free(result.file);
	free(result.md5);
	free(comp_list_sorted);

	return 0;
	
}