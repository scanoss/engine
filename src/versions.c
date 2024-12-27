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
#include "snippets.h"
#include "match.h"
#include "query.h"
#include "file.h"
#include "util.h"
#include "parse.h"
#include "debug.h"
#include "limits.h"
#include "ignorelist.h"
#include "winnowing.h"
#include "ldb.h"
#include "decrypt.h"
#include "versions.h"

/**
 * @brief Normalize component version
 * @param version version string to be processed
 * @param component component string
 */
void normalise_version(char *version, char *component)
{
	if (!version)
		return;

	char aux[MAX_FIELD_LN] = "\0";
	/* Remove leading component name from version */
	if ((version && component) && stristart(version, component))
	{
		int compt_len = strlen(component);
		sprintf(aux, "%s",version + compt_len + 1);
	}

	/* Remove unwanted leading characters from the version */
	if (version && (((*version == 'v' || *version =='r') && isdigit(version[1])) || !isalnum(*version)))
	{
		sprintf(aux, "%s",version + 1);
	} 

	/* Remove trailing ".orig" from version */
	char *orig = strstr(aux, ".orig");
	if (orig) *orig = 0;
	if (*aux)
		strcpy(version, aux);
}

/**
 * @brief Normalize versions for a match
 * @param match match to be processed
 */
void clean_versions(component_data_t *component)
{
	normalise_version(component->version, component->component);
	normalise_version(component->latest_version, component->component);
}

char * version_cleanup(char *  version, char * component)
{
	if (!version)
		return NULL;
		
	char cleaned[MAX_FIELD_LN] = "\0";
	strcpy(cleaned, version);
	normalise_version(cleaned, component);

	return strdup(cleaned);
}

static char * purl_indirection_reference[FETCH_MAX_FILES];
static int purl_indirection_index = 0;
static release_version * purl_version_list[FETCH_MAX_FILES];

void purl_latest_version_add(component_data_t * component)
{
	if (!component->purls[0] || !component->release_date || !component->version || purl_indirection_index == FETCH_MAX_FILES)
		return;

	for (int i = 0; i < purl_indirection_index; i++)
	{
		if (!strcmp(component->purls[0], purl_indirection_reference[i]))
		{
			if (strcmp(component->release_date, purl_version_list[i]->date) > 0)
			{
				strcpy(purl_version_list[i]->date, component->release_date);
				strcpy(purl_version_list[i]->version, component->version);
				scanlog("update purl version: %s update latest version to %s\n", component->purls[0], component->version);
			}
			return;
		}
	}
	purl_indirection_reference[purl_indirection_index] = strdup(component->purls[0]);
	purl_version_list[purl_indirection_index] = calloc(1, sizeof(release_version));
	strcpy(purl_version_list[purl_indirection_index]->date, component->release_date);
	strcpy(purl_version_list[purl_indirection_index]->version, component->version);
	purl_indirection_index++;
}

void purl_latest_version_search(component_data_t * component)
{
	if (!component->purls[0])
		return;
	
	for (int i = 0; i < purl_indirection_index; i++)
	{
		if (!strcmp(component->purls[0], purl_indirection_reference[i]))
		{
			release_version * release = purl_version_list[i];
			if (!component->latest_release_date || strcmp(release->date, component->latest_release_date) > 0)
			{
				scanlog("update_version_range() %s > %s, %s <- %s\n", release->date, component->release_date, component->version, release->version);
				free(component->latest_version);
				component->latest_version = strdup(release->version);
				free(component->latest_release_date);
				component->latest_release_date = strdup(release->date);
			}
			return;
		}
	}
}

void purl_latest_version_free()
{
	for (int i = 0; i < purl_indirection_index; i++)
	{
		free(purl_version_list[i]);
		free(purl_indirection_reference[i]);
	}
	purl_indirection_index = 0;
}
