// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/match.c
 *
 * Match processing and output
 *
 * Copyright (C) 2018-2020 SCANOSS.COM
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
#include "match.h"
#include "report.h"
#include "debug.h"
#include "limits.h"

bool first_file = true;
const char *matchtypes[] = {"none", "component", "file", "snippet"};
bool match_extensions = false;

/* This script replaces \ with / */
void flip_slashes(char *data)
{
	int len = strlen(data);
	for (int i = 0; i < len ; i++) if (data[i] == '\\') data[i] = '/';
}

/* Output matches in JSON format via STDOUT */
void output_matches_json(match_data *matches, scan_data *scan_ptr)
{
	scan_data scan = *scan_ptr;

	/* Files not matching are only reported with -f plain */
	if (!matches && report_format != plain) return;

	int match_counter = 0;

	flip_slashes(scan.file_path);

	/* Log slow query, if needed */
	slow_query_log(scan);

	/* Print comma separator */
	if (!quiet) if (!first_file && report_format != spdx_xml) printf("  ,\n");
	first_file = false;

	/* Open file structure */
	json_open_file(scan.file_path);

	/* Print matches */
	if (matches)
	{
		bool selected = false;

		/* Print selected match */
		for (int i = 0; i < scan_limit && *matches[i].component; i++)
		{
			if (matches[i].selected)
			{
				if (match_counter++) if (!quiet && report_format != spdx_xml) printf("  ,\n");
				print_match(scan, matches[i]);
				selected = true;
			}
		}

		/* Print matches with version ranges first */
		if (!selected) for (int i = 0; i < scan_limit && *matches[i].component; i++)
		{
			if (!matches[i].selected) if (strcmp(matches[i].version, matches[i].latest_version))
			{
				if (match_counter++) if (!quiet && report_format != spdx_xml) printf("  ,\n");
				print_match(scan, matches[i]);
			}
		}

		/* Print matches without version ranges */
		if (!selected) for (int i = 0; i < scan_limit && *matches[i].component; i++)
		{
			if (!matches[i].selected) if (!strcmp(matches[i].version, matches[i].latest_version))
			{
				if (match_counter++) if (!quiet && report_format != spdx_xml) printf("  ,\n");
				print_match(scan, matches[i]);
			}
		}
	}

	/* Print no match */
	if (!match_counter) print_json_nomatch(scan);

	json_close_file();//json_close_file(scan.file_path); MODIFICADO!!!
}

match_data match_init()
{
	match_data match;
	*match.lines = 0;
	*match.vendor = 0;
	*match.component = 0;
	*match.version = 0;
	*match.latest_version = 0;
	*match.lines = 0;
	*match.oss_lines = 0;
	*match.url = 0;
	*match.file = 0;
	*match.matched = 0;
	match.vulnerabilities = 0;
	match.path_ln = 0;
	match.selected = false;
	memcpy(match.component_md5, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", MD5_LEN);
	memcpy(match.file_md5, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", MD5_LEN);
	return match;
}

