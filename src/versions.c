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

void clean_versions(match_data *match)
{
	normalise_version(match->version, match->component);
	normalise_version(match->latest_version, match->component);
}

static bool get_purl_version_handler(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *out = ptr;

	decrypt_data(data, datalen, "url", key, subkey);

	char *CSV = calloc(datalen + 1, 1);
	memcpy(CSV, (char *) data, datalen);
	char *purl = calloc(MAX_JSON_VALUE_LEN, 1);
	char *version = calloc(MAX_JSON_VALUE_LEN, 1);
	char *component = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(component, CSV, 1, MAX_JSON_VALUE_LEN);
	extract_csv(version, CSV, 3, MAX_JSON_VALUE_LEN);
	extract_csv(purl, CSV, 6, MAX_JSON_VALUE_LEN);
	free(CSV);

	bool found = false;

	if (!strcmp(purl, out))
	{
		normalise_version(version, component);
		strcpy(out, version);
		found = true;
	}

	free(purl);
	free(version);
	free(component);

	return found;
}

/* Compare version and, if needed, update range (version-latest) */
void update_version_range(match_data *match, char *version)
{
	if (strcmp(version, match->version) < 0)
	{
		strcpy(match->version, version);
	}

	if (strcmp(version, match->latest_version) > 0)
	{
		strcpy(match->latest_version, version);
	}
}

void get_purl_version(char *version, char *purl, uint8_t *file_id)
{
	/* Pass purl in version */
	strcpy(version, purl);

	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "url");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	if (ldb_table_exists("oss", "url"))
	{
		ldb_fetch_recordset(NULL, table, file_id, false, get_purl_version_handler, version);
	}

	/* If no version returned, clear version */
	if (!strcmp(version, purl)) *version = 0;
}

/* Add version range to first match */
void add_versions(scan_data *scan, match_data *matches, file_recordset *files, uint32_t records)
{
	/* Recurse each record */
	for (int n = 0; n < records; n++)
	{
		char version[MAX_ARGLN] = "\0";
		if (!files[n].external) get_purl_version(version, matches[0].purl, files[n].url_id);
		if (*version) update_version_range(matches, version);
	}
}
