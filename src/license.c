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

/**
  * @file license.c
  * @date 27 Nov 2020 
  * @brief Contains the functions used for request the KB for licenses and generate the json output
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/license.c
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
#include "decrypt.h"

/** @brief  License sources
	 0 = Declared in component
	 1 = Declared in file with SPDX-License-Identifier
	 2 = Detected in header
	 3 = Declared in LICENSE file
	 4 = Scancode detection */
const char *license_sources[] = {"component_declared", "file_spdx_tag", "file_header", "license_file", "scancode"};

/**
 * @brief Remove invalid characters from a license name
 * @param license license string
 */
void clean_license(char *license)
{
	char *c = license;
	char byte[2] = "\0\0";
	while (*c)
	{
		*byte = *c;
		if (!isalnum(*byte) && !strstr("-+;:. ", byte))
			memmove(c, c + 1, strlen(c));
		else c++;
	}
}

/**
 * @brief Replace license with its correct SPDX identifier, if found
 * @param license license string
 */
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

/**
 * @brief Return true if license is in the osadl license list
 * @param license license string
 * @return true if it is in osadl license list
 */
bool is_osadl_license(char *license)
{
	int i = 0;
	while (osadl_licenses[i])
	{
		if (!strcmp(license,osadl_licenses[i++])) return true;
	}
	return false;
}

/**
 * @brief Return true if license is copyleft
 * @param license license string
 * @return true if it is copyleft
 */
bool is_copyleft(char *license)
{
	int i = 0;
	while (copyleft_licenses[i])
	{
		if (!strcmp(license,copyleft_licenses[i++])) return true;
	}
	return false;
}

/**
 * @brief Return true if patent hints are found in the license
 * @param license license string
 * @return true if it  has patent hints
 */
bool has_patent_hints(char *license)
{
	int i = 0;
	while (patent_hints[i])
	{
		if (!strcmp(license,patent_hints[i++])) return true;
	}
	return false;
}

/**
 * @brief Return pointer to incompatible license list (or NULL)
 * @param license license string
 * @return pointer to incompatible license list
 */
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

/**
 * @brief Output OSADL license metadata
 * @param license license string
 */
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

/**
 * @brief Print OSADL license metadata
 * @param license license string
 */
void print_osadl_license_data(char *license)
{
	printf("{\n  \"%s\": [\n", license);
	if (is_osadl_license(license))
	{
		printf("    {\n");
		printf("      \"obligations\": \"https://www.osadl.org/fileadmin/checklists/unreflicenses/%s.txt\",\n", license);
		printf("      \"copyleft\": \"%s\",\n", is_copyleft(license) ? "yes": "no");
		printf("      \"patent_hints\": \"%s\"", has_patent_hints(license) ? "yes": "no");
		char *incompatible = incompatible_licenses(license);
		if (incompatible)
			printf(",\n      \"incompatible_with\": \"%s\"\n", incompatible);
		else
			printf("\n");
		printf("    }\n");
	}
	printf("  ]\n}\n");
}

/**
 * @brief get first license function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr //TODO
 * @return //TODO
 */
bool get_first_license_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	decrypt_data(data, datalen, "license", key, subkey);

	char *CSV = calloc(datalen + 1, 1);
	memcpy(CSV, (char *) data, datalen);

	extract_csv(ptr, CSV, 2, MAX_JSON_VALUE_LEN);
	free(CSV);

	return true;
}

/**
 * @brief print license item in stdout. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr //TODO
 * @return
 */
bool print_licenses_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	match_data *match = ptr;

	if (!datalen) return false;
	decrypt_data(data, datalen, "license", key, subkey);

	char *CSV  = calloc(datalen + 1, 1);
	memcpy(CSV, data, datalen);

	char *source  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *license = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(source, CSV, 1, MAX_JSON_VALUE_LEN);
	extract_csv(license, CSV, 2, MAX_JSON_VALUE_LEN);
	free(CSV);

	clean_license(license);
	normalize_license(license);

	int src = atoi(source);

	/* Calculate CRC to avoid duplicates */
	uint32_t CRC = src + string_crc32c(license);
	bool dup = add_CRC(match->crclist, CRC);

	scanlog("Fetched license %s\n", license);
	string_clean(license);

	if (!dup && *license && (src < (sizeof(license_sources) / sizeof(license_sources[0]))))
	{
		if (!match->first_record) printf(",\n"); else printf("\n");
		match->first_record = false;

		printf("        {\n");
		printf("          \"name\": \"%s\",\n", license);
		oasdl_license_data(license);
		printf("          \"source\": \"%s\"\n", license_sources[atoi(source)]);
		printf("        }");
	}

	free(source);
	free(license);

	return false;
}

/**
 * @brief Print license for a match
 * @param match input match
 */
void print_licenses(match_data match)
{
	scanlog("Fetching license\n");

	/* Validate if license table exists */
	if (!ldb_table_exists(oss_license.db, oss_license.table))
	{
		scanlog("License table not present\n");
		return;
	}

	/* Open licenses structure */
	printf("      \"licenses\": ");
	printf("[");

	/* Clean crc list (used to avoid duplicates) */
	clean_crclist(&match);

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
		scanlog("License present in URL table\n");
		match.first_record = false;

		/* Add license to CRC list (to avoid duplicates) */
		add_CRC(match.crclist, string_crc32c(match.license));
	}
	else
	{
		match.first_record = true;
		scanlog("License NOT present in URL table\n");
	}
	
	if (!(engine_flags & DISABLE_LICENSES))
	{
		/* Look for component or file license */

		records = ldb_fetch_recordset(NULL, oss_license, match.file_md5, false, print_licenses_item, &match);
		scanlog("License for file_id license returns %d hits\n", records);

		records = ldb_fetch_recordset(NULL, oss_license, match.url_md5, false, print_licenses_item, &match);
		scanlog("License for url_id license returns %d hits\n", records);

		for (int i = 0; i < MAX_PURLS && *match.purl[i]; i++)
		{
			records = ldb_fetch_recordset(NULL, oss_license, match.purl_md5[i], false, print_licenses_item, &match);
			scanlog("License for %s license returns %d hits\n", match.purl[i], records);
		}
	}	
	printf("\n      ]");
}
