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
#include "scan.h"


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
 * @param scan_ptr scan_data_t pointer, common scan information.
 */
void output_matches_json(scan_data_t *scan)
{
	flip_slashes(scan->file_path);

	/* Log slow query, if needed */
	slow_query_log(scan);

	/* Print comma separator */
	if (!quiet)
		if (!first_file)
			printf(",");
	first_file = false;

	/* Open file structure */
	//json_open_file(scan->file_path);
	uint64_t engine_flags_aux = engine_flags;
	/* Print matches */
	if (engine_flags & DISABLE_BEST_MATCH)
	{
		printf("\"%s\": [", scan->file_path);
		bool first = true;
		for (int i=0; i < scan->matches_list_array_index; i++)
		{
			if (!first && scan->matches_list_array[i]->items && scan->matches_list_array[i]->best_match->component_list.items)
				printf(",");
			match_list_print(scan->matches_list_array[i], print_json_match, ","); //corregir
			first = false;
		}
	}
	else if (scan->matches_list_array_index > 1  && scan->max_snippets_to_process > 1)
	{
		engine_flags |= DISABLE_BEST_MATCH;
		printf("\"%s\": {\"matches\":[", scan->file_path);
		match_list_t * best_list = match_select_m_component_best(scan);
		scanlog("<<<best list items: %d>>>\n", best_list->items);
		match_list_print(best_list, print_json_match, ",");
		match_list_destroy(best_list);
	}
	else if (scan->best_match && scan->best_match->component_list.items)
	{
		printf("\"%s\": [{", scan->file_path);
		print_json_match(scan->best_match);
	}
	else
	{
		printf("\"%s\": [{", scan->file_path);
		print_json_nomatch(scan);
	}
	
	json_close_file(scan);
	engine_flags = engine_flags_aux;
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
	char comp[MAX_FIELD_LN];
	char version[MAX_FIELD_LN];
	char release_date[MAX_FIELD_LN];
	char latest_version[MAX_FIELD_LN];
	char license[MAX_FIELD_LN];
	char url[MAX_FILE_PATH];
	char purl[MAX_FILE_PATH];
	//component->path_ln = 0;
	if (!component)
		return false;
	/* Extract fields from file record */
	if (url_key)
	{
		memcpy(component->url_md5, url_key, MD5_LEN);
		if (file_path)
		{
			component->file = strdup(file_path);
			component->path_ln = strlen(file_path);
			flip_slashes(component->file);
		}
	}

	/* Extract fields from url record */
	extract_csv(vendor, (char *)url_record, 1, sizeof(vendor));
	extract_csv(comp, (char *)url_record, 2, sizeof(comp));
	extract_csv(version, (char *)url_record, 3, sizeof(version));
	extract_csv(release_date, (char *)url_record, 4, sizeof(release_date));
	extract_csv(license, (char *)url_record, 5, sizeof(license));
	extract_csv(purl, (char *)url_record, 6, sizeof(purl));
	extract_csv(url, (char *)url_record, 7, sizeof(url));
	strcpy(latest_version, version);

	flip_slashes(vendor);
	flip_slashes(comp);
	flip_slashes(version);
	flip_slashes(url);

	if (!*url || !*version || !*purl)
	{
		scanlog("Incomplete metadata for %s\n", file_path);
		return false;
	}
	component->vendor = strdup(vendor);
	component->component = strdup(comp);
	component->version = strdup(version);
	if (strlen(release_date) < 4)
			component->release_date = strdup("9999-99-99");
	else
		component->release_date = strdup(release_date);
	component->license = strdup(license);
	component->url = strdup(url);
	component->latest_version = strdup(latest_version);

	if (*purl)
	{
		component->purls[0] = strdup(purl);
		component->purls_md5[0] = malloc(MD5_LEN);
		MD5((uint8_t *)purl, strlen(purl), component->purls_md5[0]);
		component->age = get_component_age(component->purls_md5[0]);
	}
	return true;
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

/**
 * @brief Load componentes for a match processing the file recordset list.
 * For each file in the recordset we will query for the oldest url in the url table.
 * The component information will be exacted from the url record.
 * The component will be inserted in the component list for the match.
 * @param component_list component list to be filled
 * @param files recodset with candidates to be processed.
 * @param records number of records to be processed.
 * @return true 
 * @return false 
 */
static bool load_components(component_list_t * component_list, file_recordset *files, int records)
{
	scanlog("Load components\n");
	/* Load path rank */
	len_rank *path_rank = load_path_rank(files, records);

	/* Sort path_rank array from shortest to largest path */
	qsort(path_rank, SHORTEST_PATHS_QTY, sizeof(len_rank), path_struct_cmp);

	/* Dump rank contents into log */
	//dump_path_rank(path_rank, files);

	uint8_t *url_rec = calloc(LDB_MAX_REC_LN, 1); /*Alloc memory for url records */

	int min = 999; /* save the min path lenght */
	
	for (int r = 0; r < SHORTEST_PATHS_QTY; r++)
	{
		/*ignore if the path is empty */
		if (!path_rank[r].len || !*files[path_rank[r].id].path)
			continue;
		//scanlog("PATH: %s\n", files[path_rank[r].id].path);

		if (path_rank[r].len > 1 && path_rank[r].len < min)
			min = path_rank[r].len; /* update min path lenght */

		/* process until path lenght is bigger than the minimum plus one */	
		if (path_rank[r].len > min +1) 
			break;

		/* Get oldest url for this component */		
		strcpy((char *) url_rec, "9999");
		ldb_fetch_recordset(NULL, oss_url, files[path_rank[r].id].url_id, false, get_oldest_url, (void *) url_rec);

		/* Extract date from url_rec */
		char date[MAX_ARGLN]= "0";
		extract_csv(date, (char *) url_rec , 4, MAX_ARGLN);
		/* Create a new component and fill it from the url record */
		component_data_t * new_comp = calloc(1, sizeof(*new_comp));
		bool result = fill_component(new_comp, files[path_rank[r].id].url_id, files[path_rank[r].id].path, (uint8_t*) url_rec);
		if (result)
		{	
			new_comp->file_md5_ref = component_list->match_ref->file_md5;
			if (asset_declared(new_comp))
				new_comp->identified = true;
			/* If the component is valid add it to the component list */
			/* The component list is a fixed size list, of size 3 by default, this means the list will keep the free oldest components*/
			/* The oldest component will be the first in the list, if two components have the same age the purl date will untie */
			if (!component_list_add(component_list, new_comp, component_date_comparation, true))
				component_data_free(new_comp); /* Free if the componet was rejected */
		}
		else
		{
			scanlog("incomplete component");
			component_data_free(new_comp);
		}
	}
	/*
	struct comp_entry * comp = NULL;
	LIST_FOREACH(comp, &component_list->headp, entries)
		add_versions(comp->component, files, records);
	*/
	free(url_rec);
	free(path_rank);
	return true;
}


/**
 * @brief Fill match field and fill component list.
 * @param scan scan object.
 * @param match Match object.
 */
void load_matches (match_data_t *match, scan_data_t * scan)
{
	scanlog("Load matches");

	/* Compile match ranges and fill up matched percent */
	int hits = 100;
	int matched_percent = 100;

	/* Get matching line ranges (snippet match) */
	if (match->type == MATCH_SNIPPET)
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
	else
	{
		asprintf(&match->line_ranges, "all");
		asprintf(&match->oss_ranges, "all");
		asprintf(&match->matched_percent, "100%%");
	}

	uint32_t records = 0;

	/* Snippet and url match should look for the matching md5 in urls */
	if (match->type != MATCH_FILE)
	{
		/*Query to url table looking for a url match, will add the components to component list */
		records = ldb_fetch_recordset(NULL, oss_url, match->file_md5, false, handle_url_record, (void *)&match->component_list);
		scanlog("URL recordset contains %u records\n", records);
	}
	/*Collect all files from the files table matching with the match md5 being processed */
	file_recordset *files = calloc(2 * FETCH_MAX_FILES, sizeof(file_recordset));
	records = ldb_fetch_recordset(NULL, oss_file, match->file_md5, false, collect_all_files, (void *)files);
	if (records)
	{
		load_components(&match->component_list, files, records);
		if (match->component_list.headp.lh_first && match->component_list.headp.lh_first->component)
			add_versions(match->component_list.headp.lh_first->component, files, records);
	}

	free(files);

	if (!records)
		scanlog("Match type is 'none' after loading matches\n");
}



bool find_oldest(match_data_t * fp1, void * fp2)
{
	scan_data_t * scan = fp2;

	if (!fp1)
		return false;

	if(!fp1->component_list.headp.lh_first || !fp1->component_list.headp.lh_first->component || !fp1->component_list.headp.lh_first->component->version)
		return false;
	
	if(!fp1->component_list.headp.lh_first->component->release_date)
		fp1->component_list.headp.lh_first->component->release_date = strdup("9999-99-99");
	else if (!*fp1->component_list.headp.lh_first->component->release_date)
	{
		free(fp1->component_list.headp.lh_first->component->release_date);
		fp1->component_list.headp.lh_first->component->release_date = strdup("9999-99-99");
	}


	if (!scan->best_match || !scan->best_match->component_list.headp.lh_first)
		scan->best_match = fp1;
	else
	{
		if (!strcmp(scan->best_match->component_list.headp.lh_first->component->release_date, fp1->component_list.headp.lh_first->component->release_date) &&
				scan->best_match->component_list.headp.lh_first->component->age < fp1->component_list.headp.lh_first->component->age)
			scan->best_match = fp1;
		else if (strcmp(scan->best_match->component_list.headp.lh_first->component->release_date, fp1->component_list.headp.lh_first->component->release_date) > 0)
			scan->best_match = fp1;
	}

	return false; 
}

bool find_oldest_match(match_data_t * fp1, match_data_t * fp2)
{
	if (!fp1)
	{
		return true;
	}

	if (!fp2->component_list.headp.lh_first || !fp1->component_list.headp.lh_first)
		return false;

	return component_date_comparation(fp1->component_list.headp.lh_first->component, fp2->component_list.headp.lh_first->component);
}

void match_select_best(scan_data_t * scan)
{
	if (! scan->matches_list_array_index)
		return;

	for (int  i = 0; i < scan->matches_list_array_index; i++)
	{
		struct entry * item = NULL;
		LIST_FOREACH(item, &scan->matches_list_array[i]->headp, entries)
		{
			if (find_oldest_match(scan->matches_list_array[i]->best_match, item->match))
				scan->matches_list_array[i]->best_match = item->match;
		}
	}

	int max_hits = 0;
	int index = 0;
	for (int  i = 0; i < scan->matches_list_array_index; i++)
	{
		if (!scan->matches_list_array[i]->best_match)
			continue;

		if (scan->matches_list_array[i]->best_match->hits > max_hits)
		{
			static struct ranges r = {NULL, NULL, NULL};
			bool accept = true;
			if (scan->match_type == MATCH_SNIPPET && hpsm_enabled)
			{
				r = hpsm_calc(scan->matches_list_array[i]->best_match->file_md5);
				if (hpsm_enabled && r.matched && !memcmp(r.matched, "0%%", 2))
					accept = false;
			}

			if (scan->match_type == MATCH_FILE || accept)
			{
				max_hits = scan->matches_list_array[i]->best_match->hits;
				index = i;
				if (hpsm_enabled)
				{
					free(scan->matches_list_array[i]->best_match->line_ranges);
					free(scan->matches_list_array[i]->best_match->oss_ranges);
					free(scan->matches_list_array[i]->best_match->matched_percent);
					scan->matches_list_array[i]->best_match->line_ranges = r.local;
					scan->matches_list_array[i]->best_match->oss_ranges = r.remote;
					scan->matches_list_array[i]->best_match->matched_percent = r.matched;
				}
			}
		}
	}

	scan->best_match = scan->matches_list_array[index]->best_match;
	
}
/*
match_list_t * match_select_m_best(scan_data_t * scan)
{
	scanlog("<<<select_best_match_M: %d>>>>\n", scan->max_snippets_to_process);
	match_list_t * final = 	match_list_init(false,  scan->max_snippets_to_process);
	struct entry * item = NULL;
	LIST_FOREACH(item, &scan->matches.headp, entries)
		match_list_add(final, item->match, find_oldest_match, true);

	return final;
}*/

match_list_t * match_select_m_component_best(scan_data_t * scan)
{
	scanlog("<<<select_best_match_M: %d>>>>\n", scan->max_snippets_to_process);
	match_list_t * final = match_list_init(false, scan->max_snippets_to_process, scan);
	
	for (int  i = 0; i < scan->matches_list_array_index; i++)
	{
		if (!scan->matches_list_array[i]->best_match)
			continue;
		
		if (!scan->matches_list_array[i]->best_match->component_list.items)
			continue;

		match_data_t * dup_match = match_data_copy(scan->matches_list_array[i]->best_match);
		component_data_t * dup_comp = component_data_copy(scan->matches_list_array[i]->best_match->component_list.headp.lh_first->component);
		component_list_init(&dup_match->component_list, 1);
		dup_match->component_list.match_ref = dup_match;
		component_list_add(&dup_match->component_list, dup_comp, NULL, false);
		dup_match->component_list.max_items = 1; //harcoded to show only fist component in report.
		if (!match_list_add(final, dup_match, find_oldest_match, true))
			match_data_free(dup_match);
	}

	return final;

}

/**
 * @brief This function will be called for each match in a match list.
 * This process will fill the different fields for a match and also the component list.
 * @param fp1 Match to be filled.
 * @param fp2 Scan owning the match.
 * @return true: stop processing
 * @return false: continue processing.
 */
bool match_process(match_data_t * fp1, void * fp2)
{
	load_matches(fp1, (scan_data_t*) fp2);
	return false;
}
/**
 * @brief Compile matches if DISABLE_BEST_MATCH is one
 * @param scan scan data
 * @return matches list
 */
void compile_matches(scan_data_t *scan)
{
	scan->match_ptr = scan->md5;
	
	/* Gather and load match metadata */
	scanlog("Starting match: %s\n", matchtypes[scan->match_type]);
	/* Search for biggest snippet */
	if (scan->match_type == MATCH_SNIPPET)
	{
		/* Dump match map */
		if (debug_on)
			map_dump(scan);

		scanlog("%ld matches in snippet map\n", scan->matchmap_size);
		biggest_snippet(scan);
	}
	else /* Process file match */
	{
		scan->matches_list_array[0] = match_list_init(true, scan->max_snippets_to_process, scan);
		scan->matches_list_array_index = 1;
		match_data_t * match_new = calloc(1, sizeof(match_data_t));
		match_new->type = scan->match_type;
		strcpy(match_new->source_md5, scan->source_md5);
		memcpy(match_new->file_md5, scan->match_ptr, MD5_LEN);
		if (!match_list_add(scan->matches_list_array[0], match_new, NULL, false))
		{
			match_data_free(match_new);
		}
	}
	
		/* No match pointer */
		if (!scan->match_ptr)
		{
				scan->match_type = MATCH_NONE;
				scanlog("No matching file id\n");
				return;
		}
	/* Post scan processing */
	if (scan->match_type != MATCH_NONE)
	{
		/* Process each possible match filling the components list */
		for (int i=0; i < scan->matches_list_array_index; i++)
			match_list_process(scan->matches_list_array[i], match_process);
		
		/* Select best match from the universe */
		match_select_best(scan);
	}
}
