// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/attributions.c
 *
 * Attribution notices functions
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
  * @file attributions.c
  * @date 21 Feb 2021 
  * @brief Contains the functions used for generate the attributions output
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/attributions.c
  */

#include <stdbool.h>
#include <stdint.h>

#include "attributions.h"
#include "debug.h"
#include "license.h"
#include "limits.h"
#include "parse.h"
#include "util.h"
#include "mz.h"
#include "query.h"
/**
 * @brief Notices LDB function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key ldb key looking for
 * @param subkey ldb sub-key
 * @param subkey_ln //TODO  
 * @param data //TODO 
 * @param datalen //TODO  
 * @param iteration //TODO 
 * @param ptr //TODO 
 * @return //TODO  
 */
bool notices_handler(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	if (datalen != 2 * oss_attribution.key_ln) return false;
	char hexkey[oss_attribution.key_ln * 2 + 1];
	memcpy(hexkey, data, oss_attribution.key_ln * 2);
	hexkey[table->key_ln * 2] = 0;

	/* Print attribution notice header */
	char *component = (char *) ptr;
	printf("[%s]\n\n", component);

	/* Print attribution notice */
	mz_get_key(oss_notices, hexkey);
	printf("\n");

	return false;
}

/**
 * @brief atribution LDB function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr //TODO
 * @return return true or false if the atribution exist or not.
 */
bool attribution_handler(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	bool *valid = (bool *) ptr;

	if (datalen != oss_attribution.key_ln) return false;

	/* Convert key */
	uint8_t attr_id[16];
	ldb_hex_to_bin((char *) data, oss_attribution.key_ln * 2, attr_id);

	/* Define mz_job values */
	struct mz_job job;
	sprintf(job.path, "%s/oss/notices", ldb_root);
	memset(job.mz_id, 0, 2);
	job.mz = NULL;
	job.mz_ln = 0;
	job.id = NULL;
	job.ln = 0;
	job.md5[oss_attribution.key_ln] = 0;
	job.key = NULL;

	/* If file does not exist, exit with valid = false */
	if (!mz_key_exists(&job, attr_id))
	{
		*valid = false;
		return true;
	}

	return false;
}

/**
 * @brief Query to oss_atribution table with LDB to ask for the noticies for a given purl.
 * @param oss_attribution LDB attribution table.
 * @param key purl's md5 key.
 * @return true if the notices exist, false otherwise.
 */
bool purl_notices_exist(struct ldb_table oss_attribution, uint8_t *key)
{
	bool validated = true;
	fetch_recordset(oss_attribution, key, attribution_handler, &validated);
	return validated;
}

/**
 * @brief Query to oss_attribution table and print the results in stdout.
 * @param oss_attribution LDB attribution table.
 * @param key purl's md5 key
 * @param component purl
 * @return always true.
 */
bool print_notices(struct ldb_table oss_attribution, uint8_t *key, char *component)
{
	bool validated = true;
	fetch_recordset(oss_attribution, key, notices_handler, component);
	return validated;
}

/**
 * @brief Load OSADL license metadata from json file
 */
static char * notices_load_file(void)
{
	char * path = NULL;
	asprintf(&path,"/var/lib/ldb/%s/licenses.json",oss_url.db);
	uint64_t size = 0;
	if (access(path, F_OK) != 0)
	{
		scanlog("Warning: Cannot find license.json definition. Please check that %s is present\n", path);
		free(path);
		return NULL;
	}
	char * licenses_json = (char*) file_read(path, &size);
	free(path);
	return licenses_json;
}

static char * license_search_on_licenses_json(const char * license, const char * licenses_json)
{
	char * key = NULL;
	asprintf(&key,"\"rf_shortname\" : \"%s\"", license);

	char * content = strstr(licenses_json, key);
	free(key);
	
	return content;
}

static char * notice_look_for_verbatim_at_license_json(const char * license, const char * licenses_json) 
{
	char * content = license_search_on_licenses_json(license, licenses_json);
	
	if (!content)
		return NULL;
	const char notice_key[] = "\"rf_text\" :";
	content = strstr(content, notice_key);
	char * end = NULL;
	if (content)
	{
		content += strlen(notice_key);
		end = strstr(content, "\"rf_url\"");
		if (end)
		{
			end -=4;
		}
		else
		{
			scanlog("Failed to find content end\n");
		}
	}
	
	int key_len = end - content;
	char * notices = strndup(content, key_len);
	return notices;
}

/**
 * @brief Return true if purl attributions are in the KB.
 * @param oss_attribution LDB attributions table.
 * @return Return true if purl attributions are in the KB.
 */
bool check_purl_attributions(struct ldb_table oss_attributions, char * licenses_json)
{
	bool valid = true;
	if (!declared_components) return false;

	char * novalid_components = NULL;
	/* Travel declared_components */
	for (int i = 0; i < MAX_SBOM_ITEMS; i++)
	{
		char *purl = declared_components[i].purl;

		/* Exit if reached the end */
		if (!purl) break;

		/* Compare purl */
		if (*purl)
		{
			/* Get purl md5 */
			uint8_t md5[16];
			oss_attribution.hash_calc((uint8_t *)purl, strlen(purl), md5);
			if (declared_components[i].license && licenses_json && 
				license_search_on_licenses_json(declared_components[i].license, licenses_json))
			{
				continue;
			}
			else if (!ldb_key_exists(oss_attributions, md5) || !purl_notices_exist(oss_attributions, md5))
			{
					scanlog("No attribution notices or notices for %s\n", purl);
					char aux[strlen(purl) + 2];
					sprintf(aux,"%s\n", purl);
					str_cat_realloc(&novalid_components, aux);
					valid = false;
			}
		}
	}
	if (!valid)
	{
		printf("Attribution notice could not be found for this purls:\n%s\nIncomple notices will not be printed\n", novalid_components);
		free(novalid_components);
	}
	return valid;
}

/**
 * @brief Print the attribution notices for a given purl in stdout
 * @param oss_attribution LDB attributions table.
 */
void print_purl_attribution_notices(struct ldb_table oss_attributions, char * licenses_json)
{
	/* Travel declared_components */
	for (int i = 0; i < MAX_SBOM_ITEMS; i++)
	{
		/* Get purl */
		char *purl = declared_components[i].purl;
		if (!purl) break;

		if (licenses_json && declared_components[i].license)
		{
			char * license_notice = notice_look_for_verbatim_at_license_json(declared_components[i].license, licenses_json);
			if (license_notice)
				printf("%s\n",license_notice);
			
			free(license_notice);
		}
		else
		{
			/* Get purl md5 */
			uint8_t md5[16];
			oss_attribution.hash_calc((uint8_t *)purl, strlen(purl), md5);
			print_notices(oss_attributions, md5, purl);
		}
  	}
  	free(licenses_json);
}


/**
 * @brief //Validate the declared SBOM and print the attribution noticies in stdout
 * @return //TODO
 */
int attribution_notices(char * components)
{
	char * licenses_json = notices_load_file();
	/* Validate SBOM */
	declared_components = get_components(components);
	if (check_purl_attributions(oss_attribution, licenses_json))
		/* Print attribution notices */
		print_purl_attribution_notices(oss_attribution, licenses_json);

	if (declared_components) free(declared_components);
	return EXIT_SUCCESS;
}
