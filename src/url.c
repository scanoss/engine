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
  @brief //TODO
 
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
bool handle_url_record(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{
	if (!datalen && datalen >= MAX_PATH) return false;

	decrypt_data(raw_data, datalen, "url", key, subkey);

	uint8_t data[MAX_PATH] = "\0";
	memcpy(data, raw_data, datalen);
	data[datalen] = 0;

	if (ignored_asset_match(data)) return false;

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

	match.path_ln = strlen(match.url);
	match.type = url;

	add_match(-1, match, matches);
	return false;
}
/**
 * @brief Clean selected matches field in matches list 
 * @param key //TODO
**/
void clean_selected_matches(match_data *matches)
{
	for (int i = 0; i < scan_limit; i++)  matches[0].selected = false;
}

/**
 * @brief Select the purl for a match followin ta schema
 * @param schema propused schema
 * @param matches pointer to matches list
**/
bool select_purl_match(char *schema, match_data *matches)
{
	clean_selected_matches(matches);

	/* Select first match if no purl schema is provided */
	if (!schema)
	{
		matches[0].selected = 0;
		return true;
	}

	for (int i = 0; i < scan_limit && *matches[i].purl; i++)
	{
		if (!memcmp(matches[i].purl, schema, strlen(schema)))
		{
			matches[i].selected = true;
			return true;
		}
	}
	return false;
}
/**
 * @brief Select preferred URLs based on favorite purl schema
 * @param matches pointer to matches list
**/

void select_best_url(match_data *matches)
{
	if (!select_purl_match("pkg:github",matches))
		if (!select_purl_match("pkg:gitlab",matches))
			if (!select_purl_match("pkg:maven",matches))
				select_purl_match(NULL, matches);
}
/**
 * @brief Build a component URL from the provided PURL schema and actual URL
 * @param match pointer to a match
 * @param schema PURL schema
 * @param url input url
 * @param fixed none
 * @return true if succed
**/
bool build_main_url(match_data *match, char *schema, char *url, bool fixed)
{
	if (starts_with(match->purl[0], schema))
	{
		strcpy(match->main_url, url);
		if (!fixed) strcat(match->main_url, strstr(match->purl[0], "/"));
		return true;
	}
	return false;
}

/**
 * @brief Calculates a main project URL from the PURL
 * @param match pointer to a match struct
**/

void fill_main_url(match_data *match)
{
	/* URL translations */
	if (build_main_url(match, "pkg:github/", "https://github.com", false)) return;
	if (build_main_url(match, "pkg:npm/", "https://www.npmjs.com/package", false)) return;
	if (build_main_url(match, "pkg:npm/", "https://www.npmjs.com/package", false)) return;
	if (build_main_url(match, "pkg:maven/", "https://mvnrepository.com/artifact", false)) return;
	if (build_main_url(match, "pkg:pypi/", "https://pypi.org/project", false)) return;
	if (build_main_url(match, "pkg:nuget/", "https://www.nuget.org/packages", false)) return;
	if (build_main_url(match, "pkg:pypi/", "https://pypi.org/project", false)) return;
	if (build_main_url(match, "pkg:sourceforge/", "https://sourceforge.net/projects", false)) return;
	if (build_main_url(match, "pkg:gem/", "https://rubygems.org/gems/allowable", false)) return;
	if (build_main_url(match, "pkg:gitee/", "https://gitee.com", false)) return;
	if (build_main_url(match, "pkg:gitlab/", "https://gitlab.com", false)) return;

	/* Fixed, direct replacements */
	if (build_main_url(match, "pkg:kernel/", "https://www.kernel.org", true)) return;
	if (build_main_url(match, "pkg:angular/", "https://angular.io", true)) return;
}
/**
 * @brief Compare two purls
 * @param purl1 First purl
 * @param purl2 Second purl
 * @return true if the are equals
**/

bool purl_type_matches(char *purl1, char *purl2)
{
	if (!*purl1 || !*purl2) return false;
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

bool handle_purl_record(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	match_data *match = (match_data *) ptr;

	decrypt_data(data, datalen, "purl", key, subkey);

	/* Only use purl relation records */
	if (memcmp(data, "pkg:", 4)) return false;

	/* Save purl record */
	char *purl = calloc(datalen + 1, 1);
	memcpy(purl, data, datalen);
	purl[datalen] = 0;

	/* Copy purl record to match */
	for (int i = 0; i < MAX_PURLS; i++)
	{
		/* Skip purl with existing type */
		if (purl_type_matches(match->purl[i], purl)) break;

		/* Add to end of list */
		if (!*match->purl[i])
		{
			scanlog("Related PURL: %s\n", purl);
			strcpy(match->purl[i], purl);
			MD5((uint8_t *)purl, strlen(purl), match->purl_md5[i]);
			break;
		}
		/* Already exists, exit */
		if (!strcmp(match->purl[i], purl)) break;
	}

	free(purl);
	return false;
}
/**
 * @brief Fetch related purls for a match
 * @param match pointer to the match
**/

/* Fetch related purls */
void fetch_related_purls(match_data *match)
{
	if (!ldb_table_exists(oss_purl.db, oss_purl.table)) //skip purl if the table is not present
		return;

	/* Fill purls */
	for (int i = 0; i < MAX_PURLS; i++)
	{
		if (!*match->purl[i]) break;
		int purls = ldb_fetch_recordset(NULL, oss_purl, match->purl_md5[i], false, handle_purl_record, match);
		if (purls)
			scanlog("Finding related PURLs for %s returned %d matches\n", match->purl[i], purls);
		else
			scanlog("Finding related PURLs for %s returned no matches\n", match->purl[i]);
	}
}

/**
 * @brief Get the oldest release for a purl handler.
 * Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
**/

bool get_purl_first_release(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	if (!datalen) return false;

	decrypt_data(data, datalen, "purl", key, subkey);
	uint8_t *oldest = (uint8_t *) ptr;

	char purl[LDB_MAX_REC_LN + 1] = "\0";
	memcpy(purl, data, datalen);
	purl[datalen] = 0;
	/* Ignore pkg relation records */
	if (memcmp(purl, "pkg:", 4))
	{
		char release_date[MAX_ARGLN + 1] = "\0";
		extract_csv(release_date, purl, 1, MAX_ARGLN);
		if (!*oldest || (strcmp((char *)oldest, release_date) > 0))
			strcpy((char *)oldest, release_date);
	}

	return false;
}

/**
 * @brief Get first purl release date from url_rec
 * @param url url string
 * @param data[out] date
**/

void purl_release_date(char *url, char *date)
{
		*date = 0;
		char purl[MAX_ARGLN + 1] = "\0";
		extract_csv(purl, (char *) url , 6, MAX_ARGLN);

		uint8_t purl_md5[MD5_LEN];
		MD5((uint8_t *)purl, strlen(purl), purl_md5);

		ldb_fetch_recordset(NULL, oss_purl, purl_md5, false, get_purl_first_release, (void *) date);
}


/**
 * @brief Handler function for getting the oldest URL.
 * Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
**/
bool get_oldest_url(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	decrypt_data(data, datalen, "url", key, subkey);
	if (!datalen) return false;

	/* Get oldest */
	char oldest[MAX_ARGLN + 1] = "\0";
	extract_csv(oldest, (char *) ptr, 4, MAX_ARGLN);

	char url[LDB_MAX_REC_LN + 1] = "\0";
	memcpy(url, data, datalen);
	url[datalen] = 0;

	/* Skip ignored records (-b SBOM.json) */
	if (datalen) if (!ignored_asset_match((uint8_t *)url))
	{

		/* Extract date */
		char release_date[MAX_ARGLN + 1] = "\0";
		purl_release_date(url, release_date);

		/* If it is older, then we copy to oldest */
		if (!*oldest || (*release_date && (strcmp(release_date, oldest) < 0)))
		{
			scanlog("get_oldest_url() %s, %s\n", release_date, url);
			memcpy((uint8_t *) ptr, url, datalen + 1);
		}
	}
	return false;
}
