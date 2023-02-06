// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/report.c
 *
 * Match output support in JSON format
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
  * @file report.c
  * @date 10 Ago 2020
  * @brief Contains the functions used to print the json output.
  
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/report.c
  */
#include <stdio.h>
#include "debug.h"
#include "report.h"
#include "quality.h"
#include "cryptography.h"
#include "health.h"
#include "vulnerability.h"
#include "util.h"
#include "dependency.h"
#include "license.h"
#include "copyright.h"
#include "limits.h"
#include "url.h"
#include "parse.h"
#include "file.h"
#include "versions.h"
#include "hpsm.h"

uint64_t engine_flags = 0;
char  kb_version[MAX_INPUT];

/**
 * @brief Open JSON report
 */
void json_open()
{
	if (!quiet) printf("{");
}

/**
 * @brief Close main report
 */
void json_close()
{
	if (quiet) 
		return;
		
	printf("}");
	printf("\n");
}

/**
 * @brief open JSON  section for a file
 * @param filename file name string
 */
void json_open_file(char *filename)
{
	if (quiet) 
		return;
	
	if (engine_flags & DISABLE_BEST_MATCH)
		printf("\"%s\": {\"matches\":[", filename);
	else
		printf("\"%s\": [{", filename);
}

/**
 * @brief Close file section
 */
void json_close_file(scan_data_t * scan)
{
	if (quiet) 
		return;
	
	if (engine_flags & DISABLE_BEST_MATCH)
		printf("]");
	
	print_server_stats(scan);

	if (!(engine_flags & DISABLE_BEST_MATCH))
		printf("}]");
	
	if (scan->matches_list_array_index > 1  && scan->max_snippets_to_process > 1)
		printf("}");

}

void kb_version_get(void)
{
	char * kb_version_path = NULL;
	asprintf(&kb_version_path,"/var/lib/ldb/%s/version.json",oss_url.db);
	
	if (ldb_file_exists(kb_version_path))
	{
		uint64_t len = read_file(kb_version, kb_version_path, sizeof(kb_version));
		free(kb_version_path);
		
		if (len > 0)
		{
			char * end = strrchr(kb_version, '}');
			char * start = strchr(kb_version,'{');
			if (start && end)
			{
				*(end+1)=0;
				return;
			}
		}
	}
	else
		free(kb_version_path);
	sprintf(kb_version,"\"N/A\"");
}


/**
 * @brief Add server statistics to JSON
 * @param scan scan data pointer
 */
void print_server_stats(scan_data_t *scan)
{
	char hostname[MAX_ARGLN + 1];
	printf(",\"server\": {");
	printf("\"version\": \"%s\",", SCANOSS_VERSION);
	printf("\"kb_version\": %s", kb_version);
	
	if (!(engine_flags & DISABLE_SERVER_INFO))
	{
		gethostname(hostname, MAX_ARGLN + 1);
		double elapsed = (microseconds_now() - scan->timer);
		printf(",\"hostname\": \"%s\",", hostname);
		printf("\"flags\": \"%ld\",", engine_flags);
		if (ignored_assets)
			printf("\"ignored\": \"%s\",", ignored_assets);
		printf("\"elapsed\": \"%.6fs\"", elapsed / 1000000);
	}
	printf("}");

}

/**
 * @brief Return a match=none result
 * @param scan scan data pointer
 */
void print_json_nomatch(scan_data_t *scan)
{
	if (quiet) 
		return;
	if (engine_flags & DISABLE_BEST_MATCH)
		printf("{");
	printf("\"id\": \"none\"");
	//print_server_stats(scan);
	if (engine_flags & DISABLE_BEST_MATCH)
		printf("}");
	fflush(stdout);
}

/**
 * @brief Print purl array for a match
 * @param match match item
 */
void print_purl_array(component_data_t * component)
{
	//bool purl_with_version = false;
	//if (!strcmp(component->version, component->latest_version))
	//	purl_with_version = true;
	
	printf("\"purl\": [");
	for (int i = 0; i < MAX_PURLS; i++)
	{
		if (component->purls[i]) 
		{
			//Disabled do to clients compatibility
			/*if (purl_with_version)
				printf("\"%s@%s\"", component->purls[i], component->version);
			else*/
				printf("\"%s\"", component->purls[i]);
			if (i < (MAX_PURLS - 1)) if (component->purls[i + 1]) printf(",");
		} 
		else break;
	}
	printf("],");
}

/**
 * @brief Skip the first directory name for Github and Gitlab files
 * @param purl purl string
 * @param file file string
 * @return modified file string
 */
char *file_skip_release(char *purl, char *file)
{
	if (!(engine_flags & ENABLE_GITHUB_FULL_PATH) && (starts_with(purl, "pkg:github") || starts_with(purl, "pkg:gitlab")))
	{
		return skip_first_slash(file);
	}
	return file;
}


bool print_json_component(component_data_t * component)
{
	if (!component)
		return true;

	/*Check if there are some purl's md5 missing. We could do this earlier, but this is a performance optimization*/	
	for (int i = 0; i < MAX_PURLS; i++)	
	{
		if (component->purls[i] && !component->purls_md5[i])
		{
			component->purls_md5[i] = malloc(MD5_LEN);
			MD5((uint8_t *)component->purls[i], strlen(component->purls[i]), component->purls_md5[i]);
		}
	}
		
	scanlog("print component\n");
	if (engine_flags & DISABLE_BEST_MATCH)
		printf("{");
	else
		printf(",");
/* Fetch related purls */
	fetch_related_purls(component);

	/* Calculate main URL */
	fill_main_url(component);

	print_purl_array(component);

	printf("\"vendor\": \"%s\",", component->vendor);
	printf("\"component\": \"%s\",", component->component);
	
	char * version_clean = NULL;
	version_clean = version_cleanup(component->version, component->component);
	printf("\"version\": \"%s\",", version_clean ? version_clean : "");
	free(version_clean);

	version_clean = version_cleanup(component->latest_version, component->component);
	printf("\"latest\": \"%s\",", version_clean ? version_clean : "");
	free(version_clean);
	
	printf("\"url\": \"%s\",", component->main_url ? component->main_url : component->url);

	printf("\"status\": \"%s\",", component->identified ? "identified" : "pending");

	/* Print (optional download_url */
	if (engine_flags & ENABLE_DOWNLOAD_URL)
	printf("\"download_url\": \"%s\",", component->url);

	printf("\"release_date\": \"%s\",", component->release_date);
	printf("\"file\": \"%s\",", component->url_match == true ? basename(component->url) : file_skip_release(component->purls[0], component->file));

	char *url_id = md5_hex(component->url_md5);
	printf("\"url_hash\": \"%s\"", url_id);
	free(url_id);

	if (!(engine_flags & DISABLE_LICENSES))
	{
		print_licenses(component);
		printf(",%s", json_remove_invalid_char(component->license_text));
	}

	if (!(engine_flags & DISABLE_HEALTH))
	{
		print_health(component);
		if (component->health_text)
			printf(",%s", json_remove_invalid_char(component->health_text));
	}	


	if (!(engine_flags & DISABLE_DEPENDENCIES))
	{
		if (!component->dependency_text)
			print_dependencies(component);
		if (component->dependency_text)	
			printf(",%s", json_remove_invalid_char(component->dependency_text));
	}

	if (!(engine_flags & DISABLE_COPYRIGHTS))
	{
		print_copyrights(component);
		if (component->copyright_text)
			printf(",%s", component->copyright_text);
	}

	if (!(engine_flags & DISABLE_VULNERABILITIES))
	{
		print_vulnerabilities(component);
		if (component->vulnerabilities_text)
			printf(",%s", json_remove_invalid_char(component->vulnerabilities_text));
	}
	if (engine_flags & DISABLE_BEST_MATCH)	
		printf("}");
	
	fflush(stdout);
	return false;
}

bool print_json_match(struct match_data_t * match)
{
	if (!match->component_list.headp.lh_first)
	{
		scanlog("Match with no components ignored: %s", match->source_md5);
		return false;
	}
	char *file_id = md5_hex(match->file_md5);

	if (engine_flags & DISABLE_BEST_MATCH)
		printf("{");

	printf("\"id\": \"%s\"", matchtypes[match->type]);	
	printf(",\"lines\": \"%s\"", match->line_ranges);
	printf(",\"oss_lines\": \"%s\"", match->oss_ranges);
	printf(",\"matched\": \"%s\"", match->matched_percent);
	
	if ((engine_flags & ENABLE_SNIPPET_IDS) && match->type == MATCH_SNIPPET)
	{
		printf(",\"snippet_ids\": \"%s\"", match->snippet_ids);
	}

	printf(",\"file_hash\": \"%s\"", file_id);
	printf(",\"source_hash\": \"%s\"", match->source_md5);

	/* Output file_url (same as url when match type = url) */
	if (!match->component_list.headp.lh_first->component->url_match)
	{
		char *custom_url = getenv("SCANOSS_API_URL");
		printf(",\"file_url\": \"%s/file_contents/%s\"", custom_url ? custom_url : API_URL, file_id);
	}
	else
		printf(",\"file_url\": \"%s\"", match->component_list.headp.lh_first->component->url);

	free(file_id);
	
	if (!(engine_flags & DISABLE_QUALITY))
	{
		print_quality(match);
		printf(",%s", json_remove_invalid_char(match->quality_text));
	}

	if (!(engine_flags & DISABLE_CRIPTOGRAPHY))
	{
		print_cryptography(match);
		printf(",%s", json_remove_invalid_char(match->crytography_text));
	}
	if (!(engine_flags & DISABLE_BEST_MATCH))
	{
		print_json_component(match->component_list.headp.lh_first->component);
	}
	else
	{
		printf(",\"components\":[");
		
		if (match->component_list.max_items > 1)
			component_list_print(&match->component_list, print_json_component, ",");
		else
			print_json_component(match->component_list.headp.lh_first->component);

		printf("]");
	}
	
	if (engine_flags & DISABLE_BEST_MATCH)
		printf("}");
	
	fflush(stdout);
	return true;
}