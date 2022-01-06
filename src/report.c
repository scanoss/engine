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
#include "vulnerability.h"
#include "util.h"
#include "dependency.h"
#include "license.h"
#include "copyright.h"
#include "limits.h"
#include "url.h"
#include "parse.h"
#include "file.h"

uint64_t engine_flags = 0;
char  kb_version[MAX_INPUT];

/**
 * @brief Open JSON report
 */
void json_open()
{
	if (!quiet) printf("{\n");
}

/**
 * @brief Close main report
 */
void json_close()
{
	if (!quiet) printf("}\n");
}

/**
 * @brief open JSON  section for a file
 * @param filename file name string
 */
void json_open_file(char *filename)
{    
	if (!quiet) printf("  \"%s\": [\n", filename);
}

/**
 * @brief Close file section
 */
void json_close_file()
{
	if (!quiet) printf("  ]\n");
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
	
	free(kb_version_path);
	sprintf(kb_version,"\"N/A\"");
}

/**
 * @brief Add server statistics to JSON
 * @param scan scan data pointer
 */
void print_server_stats(scan_data *scan)
{
	char hostname[MAX_ARGLN + 1];
	
	gethostname(hostname, MAX_ARGLN + 1);
	double elapsed = (microseconds_now() - scan->timer);
	printf(",\n      \"server\": {\n");
	printf("        \"hostname\": \"%s\",\n", hostname);
	printf("        \"version\": \"%s\",\n", SCANOSS_VERSION);
	printf("        \"kb_version\": %s,\n", kb_version);
	
	printf("        \"flags\": \"%ld\",\n", engine_flags);
	if (ignored_assets)
		printf("        \"ignored\": \"%s\",\n", ignored_assets);
	printf("        \"elapsed\": \"%.6fs\"\n", elapsed / 1000000);
	printf("      }\n");

}

/**
 * @brief Return a match=none result
 * @param scan scan data pointer
 */
void print_json_nomatch(scan_data *scan)
{
	if (quiet) return;

	printf("    {\n");
	printf("      \"id\": \"none\"");
	print_server_stats(scan);
	printf("    }\n");
	fflush(stdout);
}

/**
 * @brief Print purl array for a match
 * @param match match item
 */
void print_purl_array(match_data match)
{
	printf("      \"purl\": [");
	for (int i = 0; i < MAX_PURLS; i++)
	{
		if (*match.purl[i]) {
			printf("\n        \"%s\"", match.purl[i]);
			if (i < (MAX_PURLS - 1)) if (*match.purl[i + 1]) printf(",");
		} else break;
	}
	printf("\n      ],\n");
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

/**
 * @brief Return match details
 * @param scan scan data
 * @param match match item
 * @param match_counter[out] pointer to match counter
 */
void print_json_match(scan_data *scan, match_data match, int *match_counter)
{
	if (quiet) return;

	/* Comma separator */
	if ((*match_counter)++) printf("  ,\n");

	/* Calculate component/vendor md5 for aggregated data queries */
	vendor_component_md5(match.vendor, match.component, match.pair_md5);

	/* Fetch related purls */
	fetch_related_purls(&match);

	/* Calculate main URL */
	fill_main_url(&match);

	printf("    {\n");
	printf("      \"id\": \"%s\",\n", matchtypes[match.type == 1 ? 2 : match.type]);
	printf("      \"status\": \"%s\",\n", scan->identified ? "identified" : "pending");
	printf("      \"lines\": \"%s\",\n", scan->line_ranges);
	printf("      \"oss_lines\": \"%s\",\n", scan->oss_ranges);

	if ((engine_flags & ENABLE_SNIPPET_IDS) && match.type == snippet)
	{
		printf("      \"snippet_ids\": \"%s\",\n", scan->snippet_ids);
	}

	printf("      \"matched\": \"%s\",\n", scan->matched_percent);

	print_purl_array(match);

	printf("      \"vendor\": \"%s\",\n", match.vendor);
	printf("      \"component\": \"%s\",\n", match.component);
	printf("      \"version\": \"%s\",\n", match.version);
	printf("      \"latest\": \"%s\",\n", match.latest_version);

	printf("      \"url\": \"%s\",\n", *match.main_url ? match.main_url : match.url);

	/* Print (optional download_url */
	if (engine_flags & ENABLE_DOWNLOAD_URL)
	printf("      \"download_url\": \"%s\",\n", match.url);

	printf("      \"release_date\": \"%s\",\n", match.release_date);
	printf("      \"file\": \"%s\",\n", match.type == 1 ? basename(match.url) : file_skip_release(match.purl[0], match.file));

	char *url_id = md5_hex(match.url_md5);
	printf("      \"url_hash\": \"%s\",\n", url_id);
	free(url_id);

	char *file_id = md5_hex(match.file_md5);

	printf("      \"file_hash\": \"%s\",\n", file_id);
	printf("      \"source_hash\": \"%s\",\n", scan->source_md5);

	/* Output file_url (same as url when match type = url) */
	if (match.type != url)
	{
		char *custom_url = getenv("SCANOSS_API_URL");
		printf("      \"file_url\": \"%s/file_contents/%s\",\n", custom_url ? custom_url : API_URL, file_id);
	}
	else
		printf("      \"file_url\": \"%s\",\n", match.url);

	free(file_id);

	print_licenses(match);

	if (!(engine_flags & DISABLE_DEPENDENCIES))
	{
		print_dependencies(match);
	}

	if (!(engine_flags & DISABLE_COPYRIGHTS))
	{
		print_copyrights(match);
	}

	if (!(engine_flags & DISABLE_VULNERABILITIES))
	{
		print_vulnerabilities(match);
	}

	if (!(engine_flags & DISABLE_QUALITY))
	{
		print_quality(match);
	}

	if (!(engine_flags & DISABLE_CRIPTOGRAPHY))
	{
		print_cryptography(match);
	}
	if (!(engine_flags & DISABLE_SERVER_INFO))
		print_server_stats(scan);
	printf("    }\n");
	fflush(stdout);
}
