// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/versions.c
 *
 * Version handling subroutines
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
  @file versions.c
  @date 31 May 2021
  @brief Contains the functions used for component's version processing
 
  Long description // TODO
  @see https://github.com/scanoss/engine/blob/master/src/versions.c
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
#include "decrypt.h"

/**
 * @brief Normalize component version
 * @param version version string to be processed
 * @param component component string
 */
void normalise_version(char *version, char *component)
{
	/* Remove leading component name from version */
	if (stristart(version, component))
		memmove(version, version + strlen(component), strlen(version + strlen(component)) + 1);

	/* Remove unwanted leading characters from the version */
	if (((*version == 'v' || *version =='r') && isdigit(version[1]))\
		|| !isalnum(*version)) memmove(version, version + 1, strlen(version) + 1);

	/* Remove trailing ".orig" from version */
	char *orig = strstr(version, ".orig");
	if (orig) *orig = 0;
}

/**
 * @brief Normalize versions for a match
 * @param match match to be processed
 */
void clean_versions(match_data *match)
{
	normalise_version(match->version, match->component);
	normalise_version(match->latest_version, match->component);
}

/**
 * @brief get purl version handler.
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
static bool get_purl_version_handler(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	release_version *release = ptr;

	if (!datalen) 
		return false;

	char *CSV = decrypt_data(data, datalen, "url", key, subkey);

	if (!CSV)
		return false;
	

	char *purl = calloc(MAX_JSON_VALUE_LEN, 1);
	char *version = calloc(MAX_JSON_VALUE_LEN, 1);
	char *component = calloc(MAX_JSON_VALUE_LEN, 1);
	char *date = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(component, CSV, 1, MAX_JSON_VALUE_LEN);
	extract_csv(version, CSV, 3, MAX_JSON_VALUE_LEN);
	extract_csv(date, CSV, 4, MAX_JSON_VALUE_LEN);
	extract_csv(purl, CSV, 6, MAX_JSON_VALUE_LEN);
	free(CSV);

	bool found = false;

	if (!strcmp(purl, release->version))
	{
		/* Copy release version, date and urlid */
		normalise_version(version, component);
		strcpy(release->version, version);
		strcpy(release->date, date);
		memcpy(release->url_id, key, LDB_KEY_LN);
		memcpy(release->url_id + LDB_KEY_LN, subkey, subkey_ln);
		found = true;
	}

	free(purl);
	free(version);
	free(component);
	free(date);

	return found;
}

/**
 * @brief Compare version and, if needed, update range (version-latest)
 * @param match pointer to match to br processed
 * @param release pointer to release version structure
 */
void update_version_range(match_data *match, release_version *release)
{
	if (!*release->date) return;

	if (strcmp(release->date, match->release_date) < 0)
	{
		scanlog("update_version_range() %s < %s, %s <- %s\n", release->date, match->release_date, match->version, release->version);
		strcpy(match->version, release->version);
		strcpy(match->release_date, release->date);
		memcpy(match->url_md5, release->url_id, MD5_LEN);
	}

	if (strcmp(release->date, match->latest_release_date) > 0)
	{
		scanlog("update_version_range() %s > %s, %s <- %s\n", release->date, match->release_date, match->version, release->version);
		strcpy(match->latest_release_date, release->date);
		strcpy(match->latest_version, release->version);
	}
}

/**
 * @brief Get ṕurl version
 * @param release[out] will be completed with the purl version
 * @param purl purl string
 * @param file_id file md5
 */
void get_purl_version(release_version *release, char *purl, uint8_t *file_id)
{
	/* Pass purl in version */
	strcpy(release->version, purl);

	ldb_fetch_recordset(NULL, oss_url, file_id, false, get_purl_version_handler, release);

	/* If no version returned, clear version */
	if (!strcmp(release->version, purl)) *release->version = 0;
}

/**
 * @brief Add version range to first match
 * @param scan scan data pointer
 * @param matches pointer to matches list
 * @param files pointer to files recordset list
 * @param records records number
 */
void add_versions(scan_data *scan, match_data *matches, file_recordset *files, uint32_t records)
{
	release_version *release = calloc(sizeof(release_version), 1);

	/* Recurse each record */
	for (int n = 0; n < records; n++)
	{
		*release->version = 0;
		*release->date = 0;
		if (!files[n].external) get_purl_version(release, matches[0].purl[0], files[n].url_id);
		if (*release->version) update_version_range(matches, release);
	}

	free(release);
}
