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
  * @file component.c
  * @date 12 Jul 2020
  * @brief Contains the functions related wiht components

  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/match.c
  */

#include "component.h"
#include "parse.h"
#include "util.h"
#include "debug.h"
#include "query.h"

/**
 * @brief Free component object
 *
 * @param data pointer to component
 */
void component_data_free(component_data_t *data)
{
    if (!data)
        return;

    free_and_null((void **)&data->vendor);
    free_and_null((void **)&data->component);
    free_and_null((void **)&data->version);
    free_and_null((void **)&data->release_date);
    free_and_null((void **)&data->latest_release_date);
    free_and_null((void **)&data->latest_version);
    free_and_null((void **)&data->license);
    free_and_null((void **)&data->url);
    free_and_null((void **)&data->file);
    free_and_null((void **)&data->main_url);
    free_and_null((void **)&data->license_text);
    free_and_null((void **)&data->dependency_text);
    free_and_null((void **)&data->vulnerabilities_text);
    free_and_null((void **)&data->copyright_text);
    free_and_null((void **)&data->health_text);

    for (int i = 0; i < MAX_PURLS; i++)
    {
        free_and_null((void **)&data->purls[i]);
        free_and_null((void **)&data->purls_md5[i]);
    }
    free_and_null((void **)&data);
}

/**
 * @brief Copy a component and create a new one
 *
 * @param in Component to be copied
 * @return component_data_t* pointer to the new compoent
 */

component_data_t *component_data_copy(component_data_t *in)
{
    component_data_t * out = calloc(1, sizeof(*out));
    out->age = in->age;
    out->component = strdup(in->component);
    out->vendor = strdup(in->vendor);
    out->version = strdup(in->version);
    out->release_date = strdup(in->release_date);
	
	if (in->file)
   		out->file = strdup(in->file);
		
    out->file_md5_ref = in->file_md5_ref;
    out->identified = in->identified;
	if(in->latest_release_date)
    	out->latest_release_date = strdup(in->latest_release_date);
    out->latest_version = strdup(in->latest_version);
    out->license = strdup(in->license);
    out->url_match = in->url_match;
    memcpy(out->url_md5, in->url_md5, MD5_LEN);
    if (in->main_url)
        out->main_url = strdup(in->main_url);
    out->url = strdup(in->url);
    out->path_ln = in->path_ln;
    for (int i = 0; i < MAX_PURLS; i++)
    {
        if (in->purls[i])
            out->purls[i] = strdup(in->purls[i]);
        else
            break;

        if (in->purls_md5[i])
        {
            out->purls_md5[i] = malloc(MD5_LEN);
            memcpy(out->purls_md5[i], in->purls_md5[i], MD5_LEN);
        }
    }

    return out;
}

/**
 * @brief Return true if asset is found in ignore_components (-b parameter)
 * @param url_record pointer to url record
 */
bool ignored_asset_match(uint8_t *url_record)
{
	if (!ignore_components)
		return false;

	/* Extract fields from URL record */
	char *vendor = calloc(LDB_MAX_REC_LN, 1);
	char *component = calloc(LDB_MAX_REC_LN, 1);
	char *purl = calloc(LDB_MAX_REC_LN, 1);

	extract_csv(vendor, (char *)url_record, 1, LDB_MAX_REC_LN);
	extract_csv(component, (char *)url_record, 2, LDB_MAX_REC_LN);
	extract_csv(purl, (char *)url_record, 6, LDB_MAX_REC_LN);

	bool found = false;

	/* Travel ignore_components */
	for (int i = 0; i < MAX_SBOM_ITEMS; i++)
	{
		char *dvendor = ignore_components[i].vendor;
		char *dcomponent = ignore_components[i].component;
		char *dpurl = ignore_components[i].purl;

		/* Exit if reached the end */
		if (!dcomponent && !dvendor && !dpurl)
			break;

		/* Compare purl */
		if (dpurl)
		{
			if (!strcmp((const char *)purl, (const char *)dpurl))
			{
				found = true;
				break;
			}
		}

		/* Compare vendor and component */
		else
		{
			bool vendor_match = !dvendor || !strcmp(vendor, dvendor);
			bool component_match = !dcomponent || !strcmp(component, dcomponent);
			if (vendor_match && component_match)
			{
				found = true;
				break;
			}
		}
	}

	free(vendor);
	free(component);
	free(purl);

	if (found)
		scanlog("Component ignored: %s\n", url_record);
	return found;
}

static char * look_for_version(char *in)
{
	if (!in)
		return NULL;
	bool is_ver = false;

	char *v = strstr(in, "-v");
	if (v && isdigit(*(v + 2)))
		is_ver = true;
	else
	{
		v = strchr(in, '.');
		if (v && isdigit(*(v + 1)) && (*(v + 2) == '.' || isdigit(*(v + 2))))
			is_ver = true;
	}

	if (is_ver)
	{
		char * p = strchr(v, '/');
		if (p)
			return (p+1);
	}

	return in;
}

void fill_component_path(component_data_t *component, char *file_path)
{
	component->file = strdup(look_for_version(file_path));
	component->path_ln = strlen(component->file);
	flip_slashes(component->file);
	component->path_depth = path_depth(component->file);
}

/**
 * @brief Fill the match structure
 * @param url_key md5 of the match url
 * @param file_path file path
 * @param url_record pointer to url record
 * @return match_data fullfilled structure
 */
bool fill_component(component_data_t *component, uint8_t *url_key, char *file_path, uint8_t *url_record)
{
	char vendor[MAX_FIELD_LN];
	char comp[MAX_FIELD_LN];
	char version[MAX_FIELD_LN];
	char release_date[MAX_FIELD_LN] = "\0";
	char latest_version[MAX_FIELD_LN];
	char license[MAX_FIELD_LN];
	char url[MAX_FILE_PATH];
	char purl[MAX_FILE_PATH];
	char rank[MAX_FIELD_LN];
	// component->path_ln = 0;
	if (!component)
		return false;
	/* Extract fields from file record */
	if (url_key)
	{
		memcpy(component->url_md5, url_key, MD5_LEN);
		if (file_path)
		{
			fill_component_path(component, file_path);
		}
	}

	/* Extract fields from url record */
	extract_csv(vendor, (char *)url_record, 1, sizeof(vendor));
	extract_csv(comp, (char *)url_record, 2, sizeof(comp));
	extract_csv(version, (char *)url_record, 3, sizeof(version));
	extract_csv(release_date, (char *)url_record, 4, sizeof(release_date));
	extract_csv(license, (char *)url_record, 5, sizeof(license));
	extract_csv(purl, (char *)url_record, 6, sizeof(purl));
	extract_csv(url, (char *)url_record, 7, sizeof(url));
	extract_csv(rank, (char *)url_record, 13, sizeof(rank)); //extracts the rank field if available
	/* Fill url stats if these are available*/
	for (int i = 0; i < 5; i++) {
		char stat[16] = "\0";
		extract_csv(stat, (char *)url_record, 8+i, sizeof(url));
		if (!*stat)
			break;
		component->url_stats[i] = atoi(stat);
	}
	strcpy(latest_version, version);

	flip_slashes(vendor);
	flip_slashes(comp);
	flip_slashes(version);
	flip_slashes(url);

	if (!*url || !*version || !*purl)
	{
		scanlog("Incomplete metadata for %s\n", file_path);
		return false;
	}
	component->vendor = strdup(vendor);
	component->component = strdup(comp);
	component->version = strdup(version);
	if (strlen(release_date) < 4)
		component->release_date = strdup("9999-99-99");
	else
		component->release_date = strdup(release_date);
	component->license = strdup(license);
	component->url = strdup(url);
	component->latest_version = strdup(latest_version);
	component->latest_release_date = strdup(component->release_date);
	if (*purl)
	{
		component->purls[0] = strdup(purl);
		component->purls_md5[0] = malloc(MD5_LEN);
		MD5((uint8_t *)component->purls[0], strlen(component->purls[0]), component->purls_md5[0]);
	}
	component->age = -1;
	if (*rank && strlen(rank) < 3)
	{
		component->rank = atoi(rank);
		//scanlog("Component rank from DB: %d\n", component->rank);
	}
	else
		component->rank = COMPONENT_DEFAULT_RANK;
	return true;
}

bool component_date_comparation(component_data_t *a, component_data_t *b)
{
	if (!*b->release_date)
		return false;
	if (!*a->release_date)
		return true;

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

	/*if the relese date is the same untie with the component age (purl)*/
	if (!strcmp(b->release_date, a->release_date) && b->age > a->age)
		return true;
	/*select the oldest release date */
	if (strcmp(b->release_date, a->release_date) < 0)
		return true;

	return false;
}
/**
 * @brief Free component_item structure
 *
 * @param comp_item to be freed
 */

void component_item_free(component_item *comp_item)
{
	if (!comp_item)
		return;
	free(comp_item->component);
	free(comp_item->vendor);
	free(comp_item->purl);
	free(comp_item->version);
}

void component_purl_md5(component_data_t * component)
{
	if (component->purls_md5[0])
		return;
		
	for (int i = 0; i < MAX_PURLS; i++)	
	{
		if (component->purls[i] && !component->purls_md5[i])
		{
			component->purls_md5[i] = malloc(oss_purl.key_ln);
			MD5((uint8_t *)component->purls[i], strlen(component->purls[i]), component->purls_md5[i]);
		}
	}
}