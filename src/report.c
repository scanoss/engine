// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/report.c
 *
 * Match output support in different formats
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

#include "debug.h"
#include "report.h"
#include "quality.h"
#include "cryptography.h"
#include "vulnerability.h"
#include "cyclonedx.h"
#include "spdx.h"
#include "util.h"
#include "dependency.h"
#include "license.h"
#include "copyright.h"
#include "limits.h"

int report_format = plain;
uint64_t engine_flags = 0;


/* Open JSON report */
void json_open()
{
	if (quiet) return;

	switch(report_format)
	{
		case plain:
			printf("{\n");
			break;

		case cyclonedx:
			cyclonedx_open();
			break;

		case spdx:
			spdx_open();
			break;
	}
}

/* Close main report */
void report_close()
{
	if (quiet) return;

	switch(report_format)
	{

		case plain:
			printf("}\n");
			break;

		case cyclonedx:
			print_matches();
			cyclonedx_close();
			break;

		case spdx:
			print_matches();
			spdx_close();
			break;

	}
}

void json_open_file(char *filename)
{    
	if (quiet) return;

	switch(report_format)
	{
		case plain:
			printf("  \"%s\": [\n", filename);
			break;
	}
}

void json_close_file()
{
	if (quiet) return;

	switch(report_format)
	{
		case plain:
			printf("  ]\n");
			break;
	}
}

/* Add server statistics to JSON */
void print_server_stats(scan_data *scan)
{
	char hostname[MAX_ARGLN + 1];
	gethostname(hostname, MAX_ARGLN + 1);
	double elapsed = (microseconds_now() - scan->timer);
	printf("      \"server\": {\n");
	printf("        \"hostname\": \"%s\",\n", hostname);
	printf("        \"version\": \"%s\",\n", SCANOSS_VERSION);
	printf("        \"flags\": \"%ld\",\n", engine_flags);
	printf("        \"elapsed\": \"%.6fs\"\n", elapsed / 1000000);
	printf("      }\n");
}

/* Return a match=none result */
void print_json_nomatch(scan_data *scan)
{
	if (quiet || report_format != plain) return;

	printf("    {\n");
	printf("      \"id\": \"none\",\n");
	print_server_stats(scan);
	printf("    }\n");
	fflush(stdout);
}

/* Return full match detail */
void print_json_match_plain(scan_data *scan, match_data match)
{
	/* Calculate component/vendor md5 for aggregated data queries */
	vendor_component_md5(match.vendor, match.component, match.pair_md5);

	printf("    {\n");
	printf("      \"id\": \"%s\",\n", matchtypes[match.type]);
	printf("      \"lines\": \"%s\",\n", scan->line_ranges);
	printf("      \"oss_lines\": \"%s\",\n", scan->oss_ranges);

	if ((engine_flags & ENABLE_SNIPPET_IDS) && match.type == snippet)
	{
		printf("      \"snippet_ids\": \"%s\",\n", scan->snippet_ids);
	}

	printf("      \"matched\": \"%s\",\n", scan->matched_percent);
	printf("      \"purl\": [\n        \"%s\"", match.purl);
	printf("\n      ],\n");
	printf("      \"vendor\": \"%s\",\n", match.vendor);
	printf("      \"component\": \"%s\",\n", match.component);
	printf("      \"version\": \"%s\",\n", match.version);
	printf("      \"latest\": \"%s\",\n", match.latest_version);

	printf("      \"url\": \"%s\",\n", match.url);
	printf("      \"release_date\": \"%s\",\n", match.release_date);
	printf("      \"file\": \"%s\",\n", match.file);

	char *url_id = md5_hex(match.url_md5);
	printf("      \"url_hash\": \"%s\",\n", url_id);
	free(url_id);

	char *file_id = md5_hex(match.file_md5);
	printf("      \"file_hash\": \"%s\",\n", file_id);
	free(file_id);

	if (!(engine_flags & DISABLE_DEPENDENCIES))
	{
		printf("      \"dependencies\": ");
		print_dependencies(match);
	}

	if (!(engine_flags & DISABLE_LICENSES))
	{
		printf("      \"licenses\": ");
		print_licenses(match);
	}

	if (!(engine_flags & DISABLE_COPYRIGHTS))
	{
		printf("      \"copyrights\": ");
		print_copyrights(match);
	}

	if (!(engine_flags & DISABLE_VULNERABILITIES))
	{
		printf("      \"vulnerabilities\": ");
		print_vulnerabilities(match);
	}

	if (!(engine_flags & DISABLE_QUALITY))
	{
		printf("      \"quality\": ");
		print_quality(match);
	}

	if (!(engine_flags & DISABLE_CRIPTOGRAPHY))
	{
		printf("      \"cryptography\": ");
		print_cryptography(match);
	}

	print_server_stats(scan);
	printf("    }\n");
	fflush(stdout);
}

/* Output contents of component_list in the requested format */
void print_matches()
{
	for (int i = 0; i < CRC_LIST_LEN && *component_list[i].purl; i++)
	{
		if (i) printf("  ,\n");
		if (report_format == cyclonedx) print_json_match_cyclonedx(i);
		else print_json_match_spdx(i);
	}
}

void print_match(scan_data *scan, match_data match, int *match_counter)
{
	add_component(&match);

	if (quiet || report_format != plain) return;

	if ((*match_counter)++) if (!quiet) printf("  ,\n");

	print_json_match_plain(scan, match);
}
