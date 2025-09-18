// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/url.c
 *
 * URL handling functions
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
  @file url.c
  @date 31 May 2021
  @brief Contains the functions used for quering the URL table.
 
  Long description // TODO
  @see https://github.com/scanoss/engine/blob/master/src/scan.c
 */

#include "match.h"
#include "report.h"
#include "debug.h"
#include "limits.h"
#include "util.h"
#include "parse.h"
#include "snippets.h"
#include "decrypt.h"
#include "ignorelist.h"
#include "versions.h"
/**
 * @brief Handle url query in th KB. 
 * Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param raw_data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr //TODO
 * @return //TODO
 */
bool handle_url_record(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{
	if (!datalen && datalen >= MAX_PATH) return false;

	char * data = decrypt_data(raw_data, datalen, *table, key, subkey);

	if (!data)
		return false;

	if (ignored_asset_match((uint8_t*) data)) 
	{
		free(data);
		return false;
	}
	int subkey_ln = table->key_ln - LDB_KEY_LN;
	component_list_t * component_list = (component_list_t*) ptr;
	
	component_data_t * new_comp = calloc(1, sizeof(*new_comp));
	bool result = fill_component(new_comp, NULL, NULL, (uint8_t*) data);
	scanlog("URL MATCH: %s\n", data);
	if (result)
	{
		/* Save match component id */
		memcpy(new_comp->url_md5, key, LDB_KEY_LN);
		memcpy(new_comp->url_md5 + LDB_KEY_LN, subkey, subkey_ln);
		new_comp->url_match = true;
		new_comp->file = strdup(new_comp->url);
		new_comp->file_md5_ref = component_list->match_ref->file_md5;
		component_list_add(component_list, new_comp, component_date_comparation, true);
	}
	else
		component_data_free(new_comp);
	
	free(data);

	return false;
}


/**
 * @brief Build a component URL from the provided PURL schema and actual URL
 * @param match pointer to a match
 * @param schema PURL schema
 * @param url input url
 * @param fixed none
 * @return true if succed
**/
bool build_main_url(component_data_t *comp, char *schema, char *url, bool fixed)
{
	if (!comp->purls[0])
		return false;

	if (starts_with(comp->purls[0], schema))
	{
		char * aux = strdup(url);
		if (!fixed) 
		{
			char * part = strchr(comp->purls[0], '/');
			/*verify with match url for casing inconsistencies */
			char * case_test = strcasestr(comp->url, part);
			if (case_test)
			{
				char * partb = strndup(case_test, strlen(part));
				asprintf(&comp->main_url,"%s%s", aux, partb);
				//strcat(match->main_url, partb);
				free(partb);
			}
			else
			{
				asprintf(&comp->main_url,"%s%s", aux, part);
			//	strcat(match->main_url, part);
			}
			free(aux);
		}
		return true;
	}
	return false;
}

/**
 * @brief Calculates a main project URL from the PURL
 * @param match pointer to a match struct
**/

void fill_main_url(component_data_t *comp)
{
	/* URL translations */
	if (build_main_url(comp, "pkg:github/", "https://github.com", false)) return;
	if (build_main_url(comp, "pkg:npm/", "https://www.npmjs.com/package", false)) return;
	if (build_main_url(comp, "pkg:npm/", "https://www.npmjs.com/package", false)) return;
	if (build_main_url(comp, "pkg:maven/", "https://mvnrepository.com/artifact", false)) return;
	if (build_main_url(comp, "pkg:pypi/", "https://pypi.org/project", false)) return;
	if (build_main_url(comp, "pkg:nuget/", "https://www.nuget.org/packages", false)) return;
	if (build_main_url(comp, "pkg:pypi/", "https://pypi.org/project", false)) return;
	if (build_main_url(comp, "pkg:sourceforge/", "https://sourceforge.net/projects", false)) return;
	if (build_main_url(comp, "pkg:gem/", "https://rubygems.org/gems", false)) return;
	if (build_main_url(comp, "pkg:gitee/", "https://gitee.com", false)) return;
	if (build_main_url(comp, "pkg:gitlab/", "https://gitlab.com", false)) return;

	/* Fixed, direct replacements */
	if (build_main_url(comp, "pkg:kernel/", "https://www.kernel.org", true)) return;
	if (build_main_url(comp, "pkg:angular/", "https://angular.io", true)) return;
}
/**
 * @brief Compare two purls
 * @param purl1 First purl
 * @param purl2 Second purl
 * @return true if the are equals
**/

bool purl_type_matches(char *purl1, char *purl2)
{
	if (!purl1 || !purl2) return false;
	int len = strlen(purl1);
	for (int i = 0; i < len; i++)
	{
		if (purl1[i] != purl2[i]) return false;
		if (purl1[i] == '/') break;
	}
	return true;
}
/**
 * @brief Purl record handle.
 * Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
**/

bool handle_purl_record(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	component_data_t *component = (component_data_t *) ptr;

	char * purl = decrypt_data(data, datalen, oss_purl, key, subkey);

	if (!purl)
		return false;

	/* Only use purl relation records */
	if (memcmp(purl, "pkg:", 4)) 
	{
		free(purl);
		return false;
	}
	
	char * c = strchr(purl, '/');
	if (!c)
		return false;
		
	char purl_type[MAX_FIELD_LN] = "\0";
	strncpy(purl_type, purl, c - purl);
	uint32_t CRC = string_crc32c(purl_type);
	bool dup = add_CRC(component->crclist, CRC);
	
	if (!dup)
	{
		/* Copy purl record to match */
		for (int i = 0; i < MAX_PURLS; i++)
		{
			/* Skip purl with existing type */
			/* Add to end of list */
			if (!component->purls[i])
			{
				scanlog("Related PURL: %s\n", purl);
				component->purls[i] = purl;
				component->purls_md5[i] = malloc(table->key_ln);
				oss_purl.hash_calc((uint8_t *)purl, strlen(purl), component->purls_md5[i]);
				return false;
			}
			/* Already exists, exit */
			else if (!strcmp(component->purls[i], purl)) break;
		}
	}
	else
	{
		scanlog("purl ignored: %s\n", purl);
	}

	free(purl);
	return false;
}
/**
 * @brief Fetch related purls for a match
 * @param match pointer to the match
**/

/* Fetch related purls */
void fetch_related_purls(component_data_t *component)
{
	if (!ldb_table_exists(oss_purl.db, oss_purl.table)) //skip purl if the table is not present
		return;
	
	uint32_t crclist[CRC_LIST_LEN];
	memset(crclist,0, sizeof(crclist));
	component->crclist = crclist;
	/* add main purl md5 if it is not ready */
	if (!component->purls_md5[0] && component->purls[0])
	{
		component->purls_md5[0] = malloc(oss_purl.key_ln);
		oss_purl.hash_calc((uint8_t *)component->purls[0], strlen(component->purls[0]), component->purls_md5[0]);
	}

	/* Fill purls */
	for (int i = 0; i < MAX_PURLS; i++)
	{
		if (!component->purls[i]) break;
		char * c = strchr(component->purls[i], '/');
		char purl_type[MAX_FIELD_LN] = "\0";
		strncpy(purl_type, component->purls[i], c - component->purls[i]);
		uint32_t CRC = string_crc32c(purl_type);
		add_CRC(component->crclist, CRC);
		
		int purls = fetch_recordset( oss_purl, component->purls_md5[i], handle_purl_record, component);
		if (purls)
			scanlog("Finding related PURLs for %s returned %d matches\n", component->purls[i], purls);
		else
			scanlog("Finding related PURLs for %s returned no matches\n", component->purls[i]);
	}
}

/**
 * @brief Get the oldest release for a purl handler.
 * Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
**/

bool get_purl_first_release(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	if (!datalen) return false;

	char * purl = decrypt_data(data, datalen, *table, key, subkey);
	uint8_t *oldest = (uint8_t *) ptr;

	if (!purl)
		return false;

	/* Ignore pkg relation records */
	if (memcmp(purl, "pkg:", 4))
	{
		char release_date[MAX_ARGLN + 1] = "\0";
		extract_csv(release_date, purl, 1, MAX_ARGLN);
		if (!*oldest || (strcmp((char *)oldest, release_date) > 0))
			strcpy((char *)oldest, release_date);
	}
	free(purl);
	return false;
}

/**
 * @brief Get first purl release date from url_rec
 * @param url url string
 * @param data[out] date
**/

void purl_release_date(char *purl, char *date)
{
	*date = 0;

	if (!ldb_table_exists(oss_purl.db, oss_purl.table)) //skip purl if the table is not present
		return; 

	uint8_t purl_md5[oss_purl.key_ln];
	oss_purl.hash_calc((uint8_t *)purl, strlen(purl), purl_md5);

	fetch_recordset( oss_purl, purl_md5, get_purl_first_release, (void *) date);
}



/**
 * @brief Handler function for getting the oldest URL.
 * Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
**/
int url_rank_max = -1; //Max url rank accepted
bool get_oldest_url(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char * url = decrypt_data(data, datalen, *table, key, subkey);
	if (!url) 
		return false;

	/* Get oldest */
	component_data_t **comp_address = ptr;
	component_data_t * comp_oldest = *comp_address;
	/* Skip ignored records (-b SBOM.json) */
	if (!ignored_asset_match((uint8_t *)url))
	{
		component_data_t * comp = calloc(1, sizeof(*comp));
		bool result = fill_component(comp, key, NULL, (uint8_t *)url);
		if (!result || (url_rank_max > 0 && comp->rank > url_rank_max))
		{
			free(url);
			component_data_free(comp);
			return false;
		}
		comp->identified = IDENTIFIED_NONE;
		asset_declared(comp);
		purl_latest_version_add(comp);

		if (!comp_oldest) {
			
			*comp_address = comp;
			free(url);
			return false;
		}
	
		bool replace = false;
		if (comp->identified > comp_oldest->identified)
		{
			scanlog("Url wins by asset identified\n");
			replace = true;
		}
		/* If it is older, then we copy to oldest */
		else if(comp->identified == comp_oldest->identified)
		{
			if (comp->rank > 0) //lower rank component will be prefered
			{
				if (comp_oldest->rank < 1 || comp->rank < comp_oldest->rank) //lowest rank is 1.
					replace = true;
			}
			else if ((!*comp_oldest->release_date && *comp->release_date) || 
				(*comp->release_date && (strcmp(comp->release_date, comp_oldest->release_date) < 0)))
				replace = true;
			else if (*comp->release_date && strcmp(comp->release_date, comp_oldest->release_date) == 0)
			{
				char purl_new[MAX_ARGLN];
				char purl_date_new[MAX_ARGLN];
				char purl_date_oldest[MAX_ARGLN];
				extract_csv(purl_new, (char *) url , 6, MAX_ARGLN);
				purl_release_date(purl_new, purl_date_new);
				purl_release_date(comp_oldest->purls[0], purl_date_oldest);
				if ((!*purl_date_oldest && *purl_date_new)|| (*purl_date_new && strcmp(purl_date_new, purl_date_oldest) < 0))
				{
					replace = true;
					scanlog("<<URL wins by purl date, %s - %s / %s -%s>>\n", purl_new, purl_date_new, comp_oldest->purls[0] ,purl_date_oldest);
				}
			}
			else if (!*comp->release_date && !*comp_oldest->release_date)
			{
				replace = true;
				scanlog("URL without release date accepted");
			}
		}

		if (replace)
		{
			component_data_free(*comp_address);
			*comp_address = comp;
		}
		else
		{
			component_data_free(comp);
		}
	}
	free(url);
	return false;
}

bool purl_vendor_component_check(component_data_t * component)
{
    char *a, *b;

    if (!component->vendor || !component->component || !component->purls[0])
        return false;
   
    a = strstr(component->purls[0], component->vendor);
    b = strstr(component->purls[0], component->component);
    
    if (a && b)
    {
        if (a == b)
            return false;
        return true;
    }
    return false;
}

int purl_source_check(component_data_t * component)
{
			// check the match source
	const char * sources[] = {
    				"github",
    				"gitlab",
					"bitbucket"};
 	const int sources_number = sizeof(sources) / sizeof(sources[0]);
	for (int i = 0; i < sources_number; i++)
	{
		if (strstr(component->purls[0], sources[i]))
			return i;
	}
	return 9999;
}