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

/* This script replaces \ with / */
void flip_slashes(char *data)
{
	int len = strlen(data);
	for (int i = 0; i < len ; i++) if (data[i] == '\\') data[i] = '/';
}

/* Output matches in JSON format via STDOUT */
void output_matches_json(match_data *matches, matchtype match_type, uint8_t *md5, char *filename, long elapsed)
{
	
	/* Files not matching are only reported with -f plain */
	if (!matches && json_format !=plain) return;

	int match_counter = 0;
	char *md5_hex = bin_to_hex(md5, 16);

	flip_slashes(filename);

	/* Log slow query, if needed */
	slow_query_log(md5_hex, filename, elapsed);  

	/* Print comma separator */
	if (!first_file) printf("  ,\n");
	first_file = false;

	/* Open file structure */
	json_open_file(filename);

	/* Print matches */
	if (matches)
	{
		bool selected = false;

		/* Print selected match */
		for (int i = 0; i < scan_limit && *matches[i].component; i++)
		{
			if (matches[i].selected)
			{
				if (match_counter++) printf("  ,\n");
				print_json_match(md5_hex, matches[i], match_type, elapsed);
				selected = true;
			}
		}

		/* Print matches with version ranges first */
		if (!selected) for (int i = 0; i < scan_limit && *matches[i].component; i++)
		{
			if (!matches[i].selected) if (strcmp(matches[i].version, matches[i].latest_version))
			{
				if (match_counter++) printf("  ,\n");
				print_json_match(md5_hex, matches[i], match_type, elapsed);
			}
		}
		/* Print matches without version ranges */
		if (!selected) for (int i = 0; i < scan_limit && *matches[i].component; i++)
		{
			if (!matches[i].selected) if (!strcmp(matches[i].version, matches[i].latest_version))
			{
				if (match_counter++) printf("  ,\n");
				print_json_match(md5_hex, matches[i], match_type, elapsed);
			}
		}
	}

	/* Print no match */
	if (!match_counter) print_json_nomatch(md5_hex, elapsed);

	json_close_file(filename);
	free(md5_hex);
}


