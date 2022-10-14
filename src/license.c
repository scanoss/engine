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
#include "license_translation.h"
#include "decrypt.h"
#include "file.h"
#include "query.h"

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
		if (!isalnum(*byte) && !strstr("/-+;:. ", byte))
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

#define OSADL_FILE_SIZE (1024 * 1024 * 1024)
char osadl_json_content [OSADL_FILE_SIZE] = "\0";

/**
 * @brief Load OSADL license metadata from json file
 */
bool osadl_load_file(void)
{
	bool result = false;
	char * path = NULL;
	asprintf(&path,"/var/lib/ldb/%s/osadl.json",oss_url.db);
	int size = read_file(osadl_json_content, path, OSADL_FILE_SIZE);
	
	if (!size)
		scanlog("Warning: Cannot find OSADL definition. Please check that %s is present\n", path);
	else
		result = true;
	
	free(path);
	return result;
}

/**
 * @brief Output OSADL license metadata
 * @param license license string
 */
int osadl_print_license(char * output, const char * license, bool more_keys_after) 
{
	int len = 0;
	char * key = NULL;
	asprintf(&key,"\"%s\":", license);

	char * content = strstr(osadl_json_content, key);
	free(key);
	
	if (!content)
		return 0;
	
	content = strchr(content, '{') + 1;
	if (content)
	{
		char * end = strchr(content, '}');
		if (end)
		{
			int key_len = end - content;
			char license_osadl[key_len+1];
			license_osadl[key_len] = '\0';
			strncpy(license_osadl, content, key_len);
			len += sprintf(output+len,"%s,", license_osadl);
		}
	}
	//print osadl version
	content = strstr(osadl_json_content, "\"osadl_updated\":");
	char * end = strchr(content, ',');
	int key_len = end - content;
	char version_key[key_len + 1];
	version_key[key_len] = '\0';
	strncpy(version_key, content, key_len);
	len += sprintf(output+len,"%s", version_key);

	if (more_keys_after)
		len += sprintf(output + len,",");
	return len;
}

/**
 * @brief Print OSADL license metadata
 * @param license license string
 */
void print_osadl_license_data(char *license)
{
	char output[MAX_FIELD_LN];
	osadl_print_license(output,license, false);
	printf("{\"%s\": {%s}}", license, output);
}

static char * json_from_license(uint32_t * crclist, char * buffer, char * license, int src, bool * first_record)
{
	scanlog("proc license %s - %d\n", license, *license);
	
	clean_license(license);
	normalize_license(license);
	string_clean(license);
	int len = 0;

	if (strlen(license) < 2)
		return buffer;
	/* Calculate CRC to avoid duplicates */
	uint32_t CRC = src + string_crc32c(license);
	bool dup = add_CRC(crclist, CRC);

	if (dup)
		return buffer;
	
	if (first_record && !*first_record)
		len += sprintf(buffer+len,",");
	else if (first_record)
		*first_record = false;
	
	len += sprintf(buffer+len,"{");
	len += sprintf(buffer+len,"\"name\": \"%s\",", license);
	len += osadl_print_license(buffer+len, license, true);
	len += sprintf(buffer+len,"\"source\": \"%s\"", license_sources[src]);
	if (!strstr(license, "LicenseRef"))
		len += sprintf(buffer+len,",\"url\": \"https://spdx.org/licenses/%s.html\"",license);
	len += sprintf(buffer+len,"}");
	return (buffer+len);
}

static char * split_in_json_array(uint32_t * crclist, char * buffer, char * license, int src, bool * first_record)
{
	/* get the first token */
	char * lic = strtok(license, "/");
	char * r = buffer;
	/* walk through other tokens */
	while(lic && *lic >= ' ') 
   	{
		r = json_from_license(crclist, r, lic, src, first_record);
		lic = strtok(NULL, "/");
	}

	return buffer;
}

void license_to_json(uint32_t * crclist, char * buffer, char * license, int src, bool * first_record)
{
	if (!strchr(license, '/'))
		json_from_license(crclist, buffer, license, src, first_record);
	else
		split_in_json_array(crclist, buffer,  license, src, first_record);
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
	char * CSV = decrypt_data(data, datalen, oss_license, key, subkey);
	if (!CSV)
		return false;
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
	component_data_t * comp = ptr;

	if (!datalen) return false;
	
	char * CSV = decrypt_data(data, datalen, oss_license, key, subkey);

	if (!CSV)
		return false;

	char *source  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *license = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(source, CSV, 1, MAX_JSON_VALUE_LEN);
	extract_csv(license, CSV, 2, MAX_JSON_VALUE_LEN);
	free(CSV);

	int src = atoi(source);

	scanlog("Fetched license %s\n", license);
	char result[MAX_FIELD_LN * 5] = "\0";
	int len = 0;

	if (strlen(license) > 2 && (src < (sizeof(license_sources) / sizeof(license_sources[0]))))
	{
		bool first_record = !(comp->license_text && *comp->license_text);
		
		license_to_json(comp->crclist, result+len, license, src, &first_record);
		str_cat_realloc(&comp->license_text, result);

	}
	free(source);
	free(license);

	return false;
}

/**
 * @brief Print license for a match
 * @param match input match
 */
void print_licenses(component_data_t * comp)
{
	scanlog("Fetching license\n");

	/* Validate if license table exists */
	if (!ldb_table_exists(oss_license.db, oss_license.table))
	{
		scanlog("License table not present\n");
		return;
	}

	/* Open licenses structure */
	char result[MAX_FIELD_LN * 5] = "\0";
	int len = 0;

	len += sprintf(result+len,"\"licenses\": ");
	len += sprintf(result+len,"[");

	/* CRC list (used to avoid duplicates) */
	uint32_t crclist[CRC_LIST_LEN];
	comp->crclist = crclist;
	uint32_t records = 0;
	bool first_record = true;

	comp->license_text = NULL;
	/* Print URL license */
	
	if (comp->license && strlen(comp->license) > 2)
	{
	
		license_to_json(crclist, result+len, comp->license, 0, &first_record);
		scanlog("License present in URL table");
		/* Add license to CRC list (to avoid duplicates) */
		add_CRC(crclist, string_crc32c(comp->license));
	}
	else
	{
		first_record = true;
		scanlog("License NOT present in URL table\n");
	}
	
	if (!(engine_flags & DISABLE_LICENSES))
	{
		/* Look for component or file license */

		records = ldb_fetch_recordset(NULL, oss_license, comp->file_md5_ref, false, print_licenses_item, comp);
		scanlog("License for file_id license returns %d hits\n", records);
		
		records = ldb_fetch_recordset(NULL, oss_license, comp->url_md5, false, print_licenses_item, comp);
		scanlog("License for url_id license returns %d hits\n", records);

		for (int i = 0; i < MAX_PURLS && comp->purls[i]; i++)
		{
			records = ldb_fetch_recordset(NULL, oss_license, comp->purls_md5[i], false, print_licenses_item, comp);
			scanlog("License for %s license returns %d hits\n", comp->purls[i], records);

			/* Calculate purl@version md5 */
			uint8_t  purlversion_md5[MD5_LEN];
			purl_version_md5(purlversion_md5, comp->purls[i], comp->version);
			
			records = ldb_fetch_recordset(NULL, oss_license, purlversion_md5, false, print_licenses_item, comp);
			scanlog("License for %s@%s license returns %d hits\n", comp->purls[i], comp->version, records);
		}
	}

	char * aux = NULL;
	if (comp->license_text && *comp->license_text)
		asprintf(&aux, "%s%s%s]", result,first_record == true ? "":"," ,comp->license_text);
	else
		asprintf(&aux, "%s]", result);
	
	free(comp->license_text);	
	comp->license_text = aux;
}
