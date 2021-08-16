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
#include "match.h"
#include "report.h"
#include "debug.h"
#include "limits.h"
#include "util.h"
#include "parse.h"
#include "snippets.h"
#include "decrypt.h"
#include "ignorelist.h"

bool handle_url_record(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *raw_data, uint32_t datalen, int iteration, void *ptr)
{
	if (!datalen && datalen >= MAX_PATH) return false;

	decrypt_data(raw_data, datalen, "url", key, subkey);

	uint8_t data[MAX_PATH] = "\0";
	memcpy(data, raw_data, datalen);
	data[datalen] = 0;

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

void clean_selected_matches(match_data *matches)
{
	for (int i = 0; i < scan_limit; i++)  matches[0].selected = false;
}

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

/* Select preferred URLs based on favorite purl schema */
void select_best_url(match_data *matches)
{
	if (!select_purl_match("pkg:github",matches))
		if (!select_purl_match("pkg:gitlab",matches))
			if (!select_purl_match("pkg:maven",matches))
				select_purl_match(NULL, matches);
}

/* Build a component URL from the provided PURL schema and actual URL */
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

/* Calculates a main project URL from the PURL */
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

bool handle_purl_record(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	match_data *match = (match_data *) ptr;

	decrypt_data(data, datalen, "purl", key, subkey);

	/* Only use purl relation records */
	if (memcmp(data, "pkg:", 4)) return false;

	data[datalen] = 0;

	/* Save purl record */
	bool added = false;
	for (int i = 0; i < MAX_PURLS; i++)
	{
		/* Add to end of list */
		if (!*match->purl[i])
		{
			strcpy(match->purl[i], (char *)data);
			MD5(data, strlen((char *)data), match->purl_md5[i]);
			added = true;
			break;
		}
		/* Already exists, exit */
		if (!strcmp(match->purl[i], (char *)data)) 
		{
			return false;
		}
	}

	/* List is full, end recordset loop */
	if (!added) return true;

	return false;
}

/* Fetch related purls */
void fetch_related_purls(match_data *match)
{
	/* Fill purls */
	for (int i = 0; i < MAX_PURLS; i++)
		ldb_fetch_recordset(NULL, oss_purl, match->purl_md5[i], false, handle_purl_record, match);
}

/* Get the oldest release for a purl */
bool get_purl_first_release(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	decrypt_data(data, datalen, "purl", key, subkey);
	uint8_t *oldest = (uint8_t *) ptr;
	data[datalen] = 0;

	if (datalen)
	{
		/* Ignore pkg relation records */
		if (memcmp(data, "pkg:", 4))
		{
			char release_date[MAX_ARGLN + 1] = "\0";
			extract_csv(release_date, (char *) data, 1, MAX_ARGLN);
			if (!*oldest || (strcmp((char *)oldest, release_date) > 0))
				strcpy((char *)oldest, release_date);
		}
	}
	return false;
}

/* Handler function for getting the oldest URL */
bool get_oldest_url(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	decrypt_data(data, datalen, "url", key, subkey);

	uint8_t *oldest = (uint8_t *) ptr;

	char url[LDB_MAX_REC_LN + 1] = "\0";
	memcpy(url, data, datalen);
	url[datalen] = 0;

	/* Skip ignored records (-b SBOM.json) */
	if (datalen) if (!ignored_asset_match((uint8_t *)url))
	{

		/* Extract purl */
		char purl[MAX_ARGLN + 1] = "\0";
		extract_csv(purl, (char *) url, 6, MAX_ARGLN);

		/* Get purl md5 */
		uint8_t purl_md5[MD5_LEN];
		MD5((uint8_t *)purl, strlen(purl), purl_md5);

		/* Query purl table to obtain first release date */
		char release_date[MAX_ARGLN + 1] = "\0";
		ldb_fetch_recordset(NULL, oss_purl, purl_md5, false, get_purl_first_release, (void *) release_date);

		/* If it is older, then we copy to oldest */
		if (!*oldest || *oldest == ',' || (*release_date && strcmp(release_date, (char *)oldest) < 0))
			sprintf((char *)oldest, "%s,%s", release_date, url);
	}
	return false;
}
