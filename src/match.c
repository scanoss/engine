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
#include "parse.h"
#include "report.h"
#include "debug.h"
#include "limits.h"
#include "util.h"
#include "snippets.h"
#include "versions.h"
#include "url.h"
#include "file.h"
#include "decrypt.h"
#include "hpsm.h"
#include "scan.h"
#include "component.h"
#include "match_list.h"
#include "dependency.h"
#include "ignorelist.h"
#include "vulnerability.h"
#include "health.h"

const char *matchtypes[] = {"none", "file", "snippet", "binary"}; /** describe the availables kinds of match */
bool match_extensions = false;									  /** global match extension flag */

char *component_hint = NULL;

/**
 * @brief Free match object memory
 * 
 * @param data pointer to match structure
 */
void match_data_free(match_data_t *data)
{
    if (!data)
        return;

    free_and_null(data->snippet_ids);
    free_and_null(data->line_ranges);
    free_and_null(data->oss_ranges);
    free_and_null(data->matched_percent);
    free_and_null(data->crytography_text);
    free_and_null(data->quality_text);
    component_list_destroy(&data->component_list);
    
    free_and_null(data);
}

/**
 * @brief Copy a match object into a new one.
 * 
 * @param in pointer to match object to be copied
 * @return match_data_t* new match object
 */

match_data_t * match_data_copy(match_data_t * in)
{
    match_data_t * out = calloc(1, sizeof(*out));
    memcpy(out->file_md5,in->file_md5,MD5_LEN);
    out->hits = in->hits;
    out->type = in->type;
    out->line_ranges = strdup(in->line_ranges);
    out->oss_ranges = strdup(in->oss_ranges);
    out->matched_percent = strdup(in->matched_percent);
    out->snippet_ids = strdup(in->snippet_ids);
    strcpy(out->source_md5, in->source_md5);
    return out;
}

/**
 * @brief Fuction to influence the selection logic using a hint.
 * 
 * @param a Component from the component list to be compared
 * @param b New component to be compared
 * @return int -1 to reject, 1 to accept or 0 if not decide
 */
static int hint_eval(component_data_t *a, component_data_t *b)
{
		/*Check for component hint in purl, select components matching with the hint */
		if (a->purls[0] && strstr(a->purls[0], component_hint) && !(b->purls[0] && strstr(b->purls[0], component_hint)))
		{
			scanlog("Reject component %s by purl hint: %s\n", b->purls[0], component_hint);
			return -1;
		}
		if (b->purls[0] && strstr(b->purls[0], component_hint) && !(a->purls[0] && strstr(a->purls[0], component_hint)))
		{
			scanlog("Accept component %s by purl hint: %s\n", b->purls[0], component_hint);
			b->identified = 1;
			return 1;
		}

		/*Check for component hint in component, select components matching with the hint */ // tODO: this should be deprecated
		if (a->component && strstr(a->component, component_hint) && !(b->component && strstr(b->purls[0], component_hint)))
		{
			scanlog("Reject component %s by hint: %s\n", b->component, component_hint);
			return -1;
		}
		if (b->component && strstr(b->component, component_hint) && !(a->component && strstr(a->purls[0], component_hint)))
		{
			scanlog("Accept component %s by hint: %s\n",  b->component, component_hint);
			b->identified = 1;
			return 1;
		}

		return 0;
}

// own function to compare strings and rate the similarity
static int string_compare(const char *string1, const char *string2)
{
	float difference = 0;
	float div = (strlen(string1) + strlen(string2)) / 2;
	if (!strcmp(string1, string2))
		return -1;

	while (*string1 != '\0' && *string2 != '\0')
	{
		if (*string1 != *string2)
		{
			difference += 1 / div;
		}

		string1++;
		string2++;
	}

	// Add the length difference if the strings have different lengths
	difference += abs((int)strlen(string1) - (int)strlen(string2)) / div;

	return ceil(difference);
}

#define PATH_LEVEL_COMP_INIT_VALUE 1000
#define PATH_LEVEL_COMP_REF 10
// Function to compare the similarity of two paths from back to front
static int paths_compare(const char *a, const char *b)
{
	// Pointers to traverse the paths from the end
	const char *ptr_a = strrchr(a, '/');
	if (!ptr_a)
		ptr_a = a;

	const char *ptr_b = strrchr(b, '/');
	if (!ptr_b)
		ptr_b = b;

	const char *ptr_a_prev = a + strlen(a) - 1;
	const char *ptr_b_prev = b + strlen(b) - 1;

	int rank = PATH_LEVEL_COMP_REF;
	// check if both path have equal lenght
	if (strlen(a) == strlen(b))
		rank--;

	while (ptr_a >= a && ptr_b >= b)
	{
		// Look for each path level
		if ((*ptr_a == '/' || ptr_a == a) && (*ptr_b == '/' || ptr_b == b))
		{
			size_t size_a = ptr_a_prev - ptr_a;
			size_t size_b = ptr_b_prev - ptr_b;

			char *level_a = strndup(ptr_a, size_a);
			char *level_b = strndup(ptr_b, size_b);

			// Compare the current levels
			rank += string_compare(*level_a == '/' ? level_a + 1 : level_a, *level_b == '/' ? level_b + 1 : level_b);

			free(level_a);
			free(level_b);

			// Move pointers
			if (ptr_a > a)
			{
				ptr_a_prev = ptr_a;
				ptr_a--;
			}
			if (ptr_b > b)
			{
				ptr_b_prev = ptr_b;
				ptr_b--;
			}
			rank--;
		}

		if (ptr_a == a && ptr_b == b)
			break;

		// look for the next levels
		if (!(*ptr_a == '/' || ptr_a == a))
			ptr_a--;

		if (!(*ptr_b == '/' || ptr_b == b))
			ptr_b--;
	}

	return rank;
}

static void evaluate_path_rank(component_data_t *comp)
{
	if (comp->path_rank == PATH_LEVEL_COMP_INIT_VALUE)
	{
		//generate the rank based on the similarity of the paths.
		comp->path_rank = paths_compare(comp->file_path_ref, comp->file);
		if (strstr(comp->file, "3rdparty"))  {
			comp->path_rank += PATH_LEVEL_COMP_REF / 2;
		}

		//modulate the result based on component information-
		if (comp->path_rank < PATH_LEVEL_COMP_REF && (strstr(comp->file_path_ref, comp->component) || strstr(comp->file_path_ref, comp->vendor)))
		{
			comp->path_rank -= PATH_LEVEL_COMP_REF / 5 + 1;
			if (strstr(comp->file_path_ref, comp->component) && strstr(comp->file_path_ref, comp->vendor))
			{
				comp->path_rank -= PATH_LEVEL_COMP_REF / 2;
			}
			if (strstr(comp->purls[0], ".mirror"))
				comp->path_rank+=PATH_LEVEL_COMP_REF / 2;
			else if (strstr(comp->purls[0], "github"))
				comp->path_rank--;
		}
	}
}

/**
 * @brief Funtion to be called as pointer when a new compoent has to be loaded in to the list
 * 
 * @param a existent component in the list
 * @param b new component to be added
 * @return true b has to be included in the list before "a"
 * @return false "a" wins, compare with the next component.
 */

static bool component_hint_date_comparation(component_data_t *a, component_data_t *b)
{
	if (declared_components)
	{
		scanlog("ASSETS eval- %d / %d\n", a->identified,  b->identified);
		if (a->identified > b->identified)
		{
			scanlog("Reject component %s@%s by SBOM\n", b->purls[0], b->version);
			return false;
		}
		
		if (b->identified > a->identified)
		{
			scanlog("Accept component %s@%s by SBOM\n", b->purls[0], b->version);
			return true;
		}
	}

	else if (component_hint)
	{
		scanlog("hint eval\n");
		int result = hint_eval(a,b);
		if (result > 0)
			return true;
		if (result < 0)
			return false;
	}
	
	if ((engine_flags & ENABLE_PATH_HINT) && a->file_path_ref && b->file_path_ref)
	{
		//evalute path rank for component a
		evaluate_path_rank(a);
		
		//evalute path rank for component b
		evaluate_path_rank(b);

		//The path_rank will be used as hint only when it has a reasonable value, in other cases the critea will be ignored.
		if (b->path_rank < PATH_LEVEL_COMP_REF / 3 + 1)
		{
			if (b->path_rank - a->path_rank < 0)
			{
				scanlog("%s wins %s by path rank %d\n", b->purls[0], a->purls[0], b->path_rank);
				return true;
			}
			if (b->path_rank - a->path_rank > 0)
			{
				scanlog("%s - %s loses %s by path rank %d/%d\n", b->purls[0],b->file,  a->purls[0], b->path_rank, a->path_rank);
				return false;
			}
		}
		else if (a->path_rank < PATH_LEVEL_COMP_REF / 3 + 1)
			return false;
	}
	if (!*b->release_date)
		return false;
	if (!*a->release_date)
		return true;
	/*if the relese date is the same untie with the component age (purl)*/
	if (!strcmp(b->release_date, a->release_date))
	{
		if (strstr(b->purls[0],"github") && !strstr(a->purls[0],"github"))
		{
			scanlog("Component prefereded by source\n");
			return true;
		}

		print_health(a);
		print_health(b);

		if (b->health_stats[0] > a->health_stats[0])
		{
			scanlog("Component accepted by health\n");
			return true;
		}
		
		if (!a->purls_md5[0] && a->purls[0])
		{
			a->purls_md5[0] = malloc(MD5_LEN);
			MD5((uint8_t *)a->purls[0], strlen(a->purls[0]), a->purls_md5[0]);
			a->age = get_component_age(a->purls_md5[0]);
		}
		
		if (!b->purls_md5[0] && b->purls[0])
		{
			b->purls_md5[0] = malloc(MD5_LEN);
			MD5((uint8_t *)b->purls[0], strlen(b->purls[0]), b->purls_md5[0]);
			b->age = get_component_age(b->purls_md5[0]);
		}
		
		if ((!a->age && b->age) || b->age > a->age)
			return true;

		if (b->age == a->age && !strcmp(a->component, b->component) &&strcmp(a->version, b->version) > 0)
			return true;
	}
	/*select the oldest release date */
	if (strcmp(b->release_date, a->release_date) < 0)
	{
		return true;
	}

	return false;
}

bool add_component_from_urlid(component_list_t *component_list, uint8_t *url_id, char *path)
{
	component_data_t *new_comp = NULL;

	ldb_fetch_recordset(NULL, oss_url, url_id, false, get_oldest_url, (void *)&new_comp);
	if (!new_comp)
		return false;
		
	fill_component_path(new_comp, path);
	/* Create a new component and fill it from the url record */

	new_comp->file_md5_ref = component_list->match_ref->file_md5;
	/* If the component is valid add it to the component list */
	/* The component list is a fixed size list, of size 3 by default, this means the list will keep the free oldest components*/
	/* The oldest component will be the first in the list, if two components have the same age the purl date will untie */
	new_comp->file_path_ref = component_list->match_ref->scan_ower->file_path;
	new_comp->path_rank = PATH_LEVEL_COMP_INIT_VALUE;

	scanlog("--- new comp: %s@%s %s %d---\n", new_comp->purls[0], new_comp->version, new_comp->release_date, new_comp->identified);
	if (!component_list_add(component_list, new_comp, component_hint_date_comparation, true))
	{
		component_data_free(new_comp); /* Free if the componet was rejected */
	}
	else
	{
		char hex_url[MD5_LEN * 2 + 1];
		ldb_bin_to_hex(new_comp->url_md5, MD5_LEN, hex_url);
		scanlog("component accepted: %s@%s - pathrank: %d - %s - %s\n", new_comp->purls[0], new_comp->version, new_comp->path_rank, new_comp->file, hex_url);
	}

	return true;
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

bool component_from_file(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{
	/*Iterations must be doubled if high accuracy is enabled*/
	int iteration_max = ((engine_flags & ENABLE_HIGH_ACCURACY) ? FETCH_MAX_FILES * 4 : FETCH_MAX_FILES);
	
	/*Return we high accuracy it is not enabled*/
	if (iteration > iteration_max * 2 && !(engine_flags & ENABLE_HIGH_ACCURACY))
		return true;

	/* Ignore path lengths over the limit */
	if (!datalen || datalen >= (MD5_LEN + MAX_FILE_PATH)) return false;

	/* Decrypt data */
	char * decrypted = decrypt_data(raw_data, datalen, oss_file, key, subkey);
	if (!decrypted)
		return false;
	
	component_list_t * component_list = (component_list_t*) ptr;
	/* Copy data to memory */

	uint8_t url_id[MD5_LEN] = {0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e}; //empty string md5
	
	if (!memcmp(raw_data,url_id, MD5_LEN)) //the md5 key of an empty string must be skipped.
		return false;

	memcpy(url_id, raw_data, MD5_LEN);
	char path[MAX_FILE_PATH+1];
	strncpy(path, decrypted, MAX_FILE_PATH);
	//check the ignore list only if the match type is MATCH_SNIPPET. TODO: remove this after remine everything.
	if (!(component_list->match_ref->type == MATCH_SNIPPET && ignored_extension(path)))
		add_component_from_urlid(component_list, url_id, path);

	free(decrypted);
	return false;
}

/**
 * @brief Fill match field and fill component list.
 * @param scan scan object.
 * @param match Match object.
 */
bool load_matches(match_data_t *match)
{
	scanlog("Load matches\n");

	/* Compile match ranges and fill up matched percent */
	int hits = 100;
	int matched_percent = 100;

	/* Get matching line ranges (snippet match) */
	if (match->type == MATCH_SNIPPET)
	{
		hits = compile_ranges(match);
		scanlog("compile_ranges returns %d hits\n", hits);

		if (hits < min_match_hits)
		{
			match->type = MATCH_NONE;
			return false;
		}
		
		float percent = (hits * 100) / match->scan_ower->total_lines;
		if (hits)
			matched_percent = floor(percent);
		if (matched_percent > 99)
			matched_percent = 99;
		if (matched_percent < 1)
			matched_percent = 1;

		asprintf(&match->matched_percent, "%u%%", matched_percent);
	}
	else if (match->type == MATCH_BINARY)
	{
		asprintf(&match->line_ranges, "n/a");
		asprintf(&match->oss_ranges, "n/a");
		asprintf(&match->matched_percent, "%d functions matched", match->hits);
	}
	else
	{
		asprintf(&match->line_ranges, "all");
		asprintf(&match->oss_ranges, "all");
		asprintf(&match->matched_percent, "100%%");
	}

	uint32_t records = 0;

	/*Query to url table looking for a url match, will add the components to component list */
	records = ldb_fetch_recordset(NULL, oss_url, match->file_md5, false, handle_url_record, (void *)&match->component_list);
	scanlog("URL recordset contains %u records\n", records);

	/*Collect all files from the files table matching with the match md5 being processed */
	records = ldb_fetch_recordset(NULL, oss_file, match->file_md5, false, component_from_file,(void *)&match->component_list);
	scanlog("Found %d file entries\n", records);

	/* Final optimization based on the available information for a component */
	/* If two components have the date date, select the one with more available information */
	
	if (match->component_list.items > 1)
	{
		struct comp_entry *item = NULL;
		LIST_FOREACH(item, &match->component_list.headp, entries)
		{
			if (!item->entries.le_next || !item->entries.le_next->component)
				break;
			
			if(!item->component->dependency_text || strlen(item->component->dependency_text) < 4)	
				print_dependencies(item->component);
			
			if(!item->component->vulnerabilities_text || strlen(item->component->vulnerabilities_text) < 4)	
				print_vulnerabilities(item->component);
						
			struct comp_entry *item2 = NULL;
			for (item2 = item->entries.le_next; item2 != NULL; item2 = item2->entries.le_next)
			{
				if(!item2->component->dependency_text || strlen(item2->component->dependency_text) < 4)	
					print_dependencies(item2->component);
			
				if(!item->component->vulnerabilities_text || strlen(item->component->vulnerabilities_text) < 4)	
					print_vulnerabilities(item2->component);
				
				if (!item2->component->vulnerabilities && !item2->component->dependencies)
					continue;
				
				scanlog("%s vs %s tiebreak\n", item->component->purls[0], item2->component->purls[0]);

				if ((!item->component->dependencies && item2->component->dependencies) ||
					(!item->component->vulnerabilities && item2->component->vulnerabilities))
				{
					scanlog("Component permuted due to dependency/vulnerabilities tiebreak\n");
					component_data_t * aux = item->component;
					item->component = item2->component;
					item2->component = aux;
					break;
				}
			}
		}
	}

	if (engine_flags & DISABLE_BEST_MATCH)
	{
		struct comp_entry *item = NULL;
		LIST_FOREACH(item, &match->component_list.headp, entries)
		{
			//add_versions(item->component, files, records < files_records_max ? records : files_records_max);
			purl_latest_version_search(item->component);
		}
	}

	else if (match->component_list.items && match->component_list.headp.lh_first->component)
	{
		//add_versions(match->component_list.headp.lh_first->component, files, records < files_records_max ? records : files_records_max);
		purl_latest_version_search(match->component_list.headp.lh_first->component);
	}
	purl_latest_version_free();

	if (!records)
		scanlog("Match type is 'none' after loading matches\n");

	return false;
}

bool find_oldest(match_data_t *fp1, void *fp2)
{
	scan_data_t *scan = fp2;

	if (!fp1)
		return false;

	if (!fp1->component_list.headp.lh_first || !fp1->component_list.headp.lh_first->component || !fp1->component_list.headp.lh_first->component->version)
		return false;

	if (!fp1->component_list.headp.lh_first->component->release_date)
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

/**
 * @brief Find the oldest match in the matches list, comparing the first component (the oldest) of each match.
 * 
 * @param fp1 first match to be compared
 * @param fp2 second match to be compared
 * @return true 
 * @return false 
 */

bool find_oldest_match(match_data_t *fp1, match_data_t *fp2)
{
	if (!fp1)
	{
		return true;
	}

	if (!fp2->component_list.headp.lh_first)
		return false;
	if (!fp1->component_list.headp.lh_first)
		return true;
	
	return component_date_comparation(fp1->component_list.headp.lh_first->component, fp2->component_list.headp.lh_first->component);
}
/**
 * @brief Select the best match from the matches list
 * 
 * @param scan scan to be analized
 */
void match_select_best(scan_data_t *scan)
{
	scanlog("match_select_best\n");
	if (!scan->matches_list_array_index)
		return;

	for (int i = 0; i < scan->matches_list_array_index; i++)
	{
		struct entry *item = NULL;
		LIST_FOREACH(item, &scan->matches_list_array[i]->headp, entries)
		{
			if (find_oldest_match(scan->matches_list_array[i]->best_match, item->match))
				scan->matches_list_array[i]->best_match = item->match;
		}
	}

	for (int i = 0; i < scan->matches_list_array_index; i++)
	{
		if (!scan->matches_list_array[i]->best_match)
			continue;
		struct entry *item = NULL;
		
		scanlog("Final logic for list %d: \n", i);

		LIST_FOREACH(item, &scan->matches_list_array[i]->headp, entries)
		{
			if (!item->match->component_list.headp.lh_first)
				continue;

			component_data_t  * best_match_component = scan->matches_list_array[i]->best_match->component_list.headp.lh_first->component;
			component_data_t * match_component = item->match->component_list.headp.lh_first->component;
			scanlog("%s -%s - %d VS %s - %s - %d\n",
					best_match_component->purls[0],
					best_match_component->release_date,
					scan->matches_list_array[i]->best_match->hits,
					match_component->purls[0], match_component->release_date, item->match->hits);
			
			if (!strcmp(best_match_component->purls[0],match_component->purls[0]))
			{
				if (abs(scan->matches_list_array[i]->best_match->hits - item->match->hits) <= 2 &&
					find_oldest_match(scan->matches_list_array[i]->best_match, item->match))
				{
					scanlog("Replacing best match for an older version with equal hits\n");
					scan->matches_list_array[i]->best_match = item->match;
				}
				else if (scan->matches_list_array[i]->best_match->hits + 1 < item->match->hits)
				{
					scanlog("Replacing best match for a newers version with more hits\n");
					scan->matches_list_array[i]->best_match = item->match;
				}

			}
			else if (scan->matches_list_array[i]->best_match->hits > item->match->hits)
			{
				scanlog("Hits are lower than the best match, no more comparations are needed. Exiting...\n");
				break;
			}

			if (!best_match_component->identified && match_component->identified)
			{
				scanlog("Replacing best match for a prefered component\n");
				scan->matches_list_array[i]->best_match = item->match;
			}	
		}
	}

	int max_hits = 0;
	int index = 0;
	//Look for the best of the best (for multiple snippet analysis)
	if (scan->match_type == MATCH_SNIPPET)
	{
		index = -1;
		for (int i = 0; i < scan->matches_list_array_index; i++)
		{
			if (!scan->matches_list_array[i]->best_match)
				continue;

			if (scan->matches_list_array[i]->best_match->hits > max_hits)
			{
				if (hpsm_enabled) // update the line ranges if HPSM is enabled.
				{
					static struct ranges r = {NULL, NULL, NULL};
					r = hpsm_calc(scan->matches_list_array[i]->best_match->file_md5);
					scanlog("HPSM range: %s\n", r.local);
					if (*r.local && strcmp(r.local,"-1")) //check if HPSM was able to run
					{
						if (hpsm_enabled && r.matched && !memcmp(r.matched, "0%%", 2))
						{
							scan->matches_list_array[i]->best_match->type = MATCH_NONE;
						}
						else
						{
							free(scan->matches_list_array[i]->best_match->line_ranges);
							free(scan->matches_list_array[i]->best_match->oss_ranges);
							free(scan->matches_list_array[i]->best_match->matched_percent);
							scan->matches_list_array[i]->best_match->line_ranges = r.local;
							scan->matches_list_array[i]->best_match->oss_ranges = r.remote;
							scan->matches_list_array[i]->best_match->matched_percent = r.matched;

							max_hits = scan->matches_list_array[i]->best_match->hits;
							index = i;
						}
						continue;
					}
				}

				max_hits = scan->matches_list_array[i]->best_match->hits;
				index = i;
			}
		}
	}

	//if we have multiple snippets match, the best of the best is the most hitted.
	if (index >= 0)
		scan->best_match = scan->matches_list_array[index]->best_match;
	/*if the component of the best match was identified in the assets list, return none*/
	if (!scan->best_match || !scan->best_match->component_list.items || ((engine_flags & DISABLE_REPORT_IDENTIFIED) && scan->best_match->component_list.headp.lh_first->component->identified))
	{
		scan->match_type = MATCH_NONE;
		scanlog("Match without components or declared in sbom\n");
	}
}

match_list_t *match_select_m_component_best(scan_data_t *scan)
{
	scanlog("<<<select_best_match_M: %d>>>>\n", scan->max_snippets_to_process);
	match_list_t *final = match_list_init(false, scan->max_snippets_to_process);

	for (int i = 0; i < scan->matches_list_array_index; i++)
	{
		if (!scan->matches_list_array[i]->best_match)
			continue;

		if (!scan->matches_list_array[i]->best_match->component_list.items)
			continue;

		match_data_t *dup_match = match_data_copy(scan->matches_list_array[i]->best_match);
		component_data_t *dup_comp = component_data_copy(scan->matches_list_array[i]->best_match->component_list.headp.lh_first->component);

		component_list_init(&dup_match->component_list, 1);
		dup_match->component_list.match_ref = dup_match;
		component_list_add(&dup_match->component_list, dup_comp, NULL, false);
		dup_match->component_list.max_items = 1; // harcoded to show only fist component in report.
		if (!match_list_add(final, dup_match, find_oldest_match, true))
			match_data_free(dup_match);
	}

	return final;
}



/**
 * @brief Select the best match from the matches list
 * 
 * @param scan scan to be analized
 */
void compile_matches(scan_data_t *scan)
{
	scan->match_ptr = scan->md5;

	/* Gather and load match metadata */
	scanlog("Starting match: %s\n", matchtypes[scan->match_type]);
	/* Search for biggest snippet */
	if (scan->match_type == MATCH_SNIPPET || scan->match_type == MATCH_BINARY)
	{
		/* Dump match map */
		if (debug_on)
			map_dump(scan);

		scanlog("%ld matches in snippet map\n", scan->matchmap_size);
		biggest_snippet(scan);
	}
	else /* Process file match */
	{
		scan->matches_list_array[0] = match_list_init(true, scan->max_snippets_to_process);
		scan->matches_list_array_index = 1;
		match_data_t *match_new = calloc(1, sizeof(match_data_t));
		match_new->type = scan->match_type;
		strcpy(match_new->source_md5, scan->source_md5);
		memcpy(match_new->file_md5, scan->match_ptr, MD5_LEN);
		match_new->scan_ower = scan;
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
		for (int i = 0; i < scan->matches_list_array_index; i++)
			match_list_process(scan->matches_list_array[i], load_matches);

		/* Select best match from the universe */
		match_select_best(scan);
	}
}
