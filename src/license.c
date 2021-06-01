// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/license.c
 *
 * "License" data aggregation functions
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
#include <stdbool.h>
#include <stdint.h>

#include "ignorelist.h"
#include "limits.h"
#include "license.h"
#include "debug.h"
#include "util.h"
#include "parse.h"
#include "osadl_metadata.h"
#include "license_translation.h"

const char *license_sources[] = {"component_declared", "file_spdx_tag", "file_header"};

/* Remove invalid characters from a license name */
void clean_license(char *license)
{
	char *c = license;
	char byte[2] = "\0\0";
	while (*c)
	{
		*byte = *c;
		if (!isalnum(*byte) && !strstr(" -+;:.", byte))
			memmove(c, c + 1, strlen(c));
		else c++;
	}
}

/* Replace license with its correct SPDX identifier, if found */
void normalize_license(char *license)
{
	for (int i = 0; license_normalization[i]; i++)
	{
		char def[MAX_ARGLN];
		strcpy(def, license_normalization[i]);
		char *token;

		/* get the first token */
		token = strtok(def, ",");

		char *spdx = token;

		/* walk through other tokens */
		while (token != NULL)
		{
			if (stricmp(license, token))
			{
				strcpy(license, spdx);
				return;
			}
			token = strtok(NULL, ",");
		}
	}
}

/* Return true if license is in the osadl license list */
bool is_osadl_license(char *license)
{
	int i = 0;
	while (osadl_licenses[i])
	{
		if (!strcmp(license,osadl_licenses[i++])) return true;
	}
	return false;
}

/* Return true if license is copyleft */
bool is_copyleft(char *license)
{
	int i = 0;
	while (copyleft_licenses[i])
	{
		if (!strcmp(license,copyleft_licenses[i++])) return true;
	}
	return false;
}

/* Return true if patent hints are found in the license */
bool has_patent_hints(char *license)
{
	int i = 0;
	while (patent_hints[i])
	{
		if (!strcmp(license,patent_hints[i++])) return true;
	}
	return false;
}

/* Return pointer to incompatible license list (or NULL) */
char *incompatible_licenses(char *license)
{
	int i = 0;
	int lic_ln = strlen(license);
	while (incompatibilities[i])
	{
		if (!strncmp(license,incompatibilities[i], lic_ln))
		{
			/* Skip colon and space after license name */
			return (char *) incompatibilities[i] + lic_ln + 2;
		}
		i++;
	}
	return NULL;
}

/* Output OSADL license metadata */
void oasdl_license_data(char *license)
{
	if (is_osadl_license(license))
	{
		printf("          \"obligations\": \"https://www.osadl.org/fileadmin/checklists/unreflicenses/%s.txt\",\n", license);
		printf("          \"copyleft\": \"%s\",\n", is_copyleft(license) ? "yes": "no");
		printf("          \"patent_hints\": \"%s\",\n", has_patent_hints(license) ? "yes": "no");
		char *incompatible = incompatible_licenses(license);
		if (incompatible)
		printf("          \"incompatible_with\": \"%s\",\n", incompatible);
	}
}

/* Print OSADL license metadata */
void print_osadl_license_data(char *license)
{
	printf("{\n  \"%s\": [\n", license);
	if (is_osadl_license(license))
	{
		printf("    {\n");
		printf("      \"obligations\": \"https://www.osadl.org/fileadmin/checklists/unreflicenses/%s.txt\",\n", license);
		printf("      \"copyleft\": \"%s\",\n", is_copyleft(license) ? "yes": "no");
		printf("      \"patent_hints\": \"%s\",\n", has_patent_hints(license) ? "yes": "no");
		char *incompatible = incompatible_licenses(license);
		if (incompatible)
			printf("      \"incompatible_with\": \"%s\"\n", incompatible);
		printf("    }\n");
	}
	printf("  ]\n}\n");
}

bool get_first_license_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *CSV = calloc(datalen + 1, 1);
	memcpy(CSV, (char *) data, datalen);

	extract_csv(ptr, CSV, 2, MAX_JSON_VALUE_LEN);
	free(CSV);

	return true;
}

bool print_licenses_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	match_data *match = ptr;

	char *CSV  = calloc(datalen + 1, 1);
	memcpy(CSV, data, datalen);

	char *source  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *license = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(source, CSV, 1, MAX_JSON_VALUE_LEN);
	extract_csv(license, CSV, 2, MAX_JSON_VALUE_LEN);
	free(CSV);

	clean_license(license);
	normalize_license(license);

	/* Calculate CRC to avoid duplicates */
	uint32_t CRC = string_crc32c(source) + string_crc32c(license);
	bool dup = add_CRC(match->crclist, CRC);

	int src = atoi(source);

	scanlog("Fetched license %s\n", license);
	printable_only(license);
	bool reported = false;

	if (!dup && *license && (src < (sizeof(license_sources) / sizeof(license_sources[0]))))
	{
		if (iteration) printf(",\n"); else printf("\n");
		printf("        {\n");
		printf("          \"name\": \"%s\",\n", license);
		oasdl_license_data(license);
		printf("          \"source\": \"%s\"\n", license_sources[atoi(source)]);
		printf("        }");
		reported = true;
	}

	free(source);
	free(license);

	return reported;
}

void get_license(match_data match, char *license)
{
	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "license");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	uint32_t records = 0;

	if (ldb_table_exists("oss", "license"))
	{
		records = ldb_fetch_recordset(NULL, table, match.file_md5, false, get_first_license_item, license);
		if (!records)
			records = ldb_fetch_recordset(NULL, table, match.url_md5, false, get_first_license_item, license);
		if (!records)
			records = ldb_fetch_recordset(NULL, table, match.pair_md5, false, get_first_license_item, license);
	}
}

void print_licenses(match_data match)
{
	printf("[");

	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "license");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	/* Clean crc list (used to avoid duplicates) */
	for (int i = 0; i < CRC_LIST_LEN; i++) match.crclist[i] = 0;

	uint32_t records = 0;
	clean_license(match.license);

	/* Print URL license */
	if (*match.license)
	{
		normalize_license(match.license);
		printf("\n        {\n");
		printf("          \"name\": \"%s\",\n", match.license);
		oasdl_license_data(match.license);
		printf("          \"source\": \"%s\"\n", license_sources[0]);
		printf("        }");
	}

	/* Look for component or file license */
	else if (ldb_table_exists("oss", "license"))
	{
		records = ldb_fetch_recordset(NULL, table, match.file_md5, false, print_licenses_item, &match);
		if (records) scanlog("File license returns hits\n");
		if (!records)
		{
			records = ldb_fetch_recordset(NULL, table, match.url_md5, false, print_licenses_item, &match);
			if (records) scanlog("Component license returns hits\n");
		}
		if (!records)
		{
			records = ldb_fetch_recordset(NULL, table, match.pair_md5, false, print_licenses_item, &match);
			if (records) scanlog("Vendor/component license returns hits\n");
		}
	}

	printf("\n      ],\n");
}

