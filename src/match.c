// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/match.c
 *
 * Match processing and ouput
 *
 * Copyright (C) 2018-2020 SCANOSS LTD
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


/* Trim string at first non-printable char */
void printable_only(char *text)
{
	for (int i = 0; i < strlen(text); i++)
		if (text[i] < '"' || text[i] > 'z') text[i] = 0;
}

bool print_licenses_item(uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *source  = calloc(ldb_max_recln, 1);
	char *license = calloc(ldb_max_recln, 1);

	extract_csv(source, (char *) data, 1, ldb_max_recln);
	extract_csv(license,(char *) data, 2, ldb_max_recln);

	printable_only(source);
	printable_only(license);

	if (*source && *license)
	{
		if (iteration) printf(",\n"); else printf("\n");
		printf("        {\n");
		printf("          \"name\": \"%s\",\n", license);
		printf("          \"source\": \"%s\"\n", source);
		printf("        }");
	}

	free(source);
	free(license);

	return false;
}

void print_licenses(uint8_t *key, bool comma)
{
	printf("[");

	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "license");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	uint32_t records = 0;

	if (ldb_table_exists("oss", "license"))
		records = ldb_fetch_recordset(table, key, print_licenses_item, NULL);

	if (records) printf("\n      ");
	printf("]");
	if (comma) printf(",");
	printf("\n");

}

bool print_dependencies_item(uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *source = calloc(ldb_max_recln, 1);
	char *type   = calloc(ldb_max_recln, 1);
	char *dep    = calloc(ldb_max_recln, 1);

	extract_csv(source, (char *) data, 1, ldb_max_recln);
	extract_csv(type,   (char *) data, 2, ldb_max_recln);
	extract_csv(dep,    (char *) data, 3, ldb_max_recln);

	printable_only(source);
	printable_only(type);
	printable_only(dep);

	if (*source && *type && *dep)
	{
		if (iteration) printf(",\n"); else printf("\n");
		printf("        {\n");
		printf("          \"name\": \"%s\",\n", dep);
		printf("          \"type\": \"%s\",\n", type);
		printf("          \"source\": \"%s\"\n", source);
		printf("        }");
	}

	free(source);
	free(type);
	free(dep);
	return false;
}

void print_dependencies(uint8_t *key, bool comma)
{
	printf("[");

	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "dependency");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	uint32_t records = 0;

	if (ldb_table_exists("oss", "dependency"))
		records = ldb_fetch_recordset(table, key, print_dependencies_item, NULL);

	if (records) printf("\n      ");
	printf("]");
	if (comma) printf(",");
	printf("\n");
}

void component_vendor_md5(char *component, char *vendor, uint8_t *out)
{
	char pair[1024] = "\0";
	if (strlen(component) + strlen(vendor) + 2 >= 1024) return;
	sprintf(pair, "%s/%s", component, vendor);
	MD5((uint8_t *)pair, strlen(pair), out);
}

void print_json_match(char *md5_hex, match_data match, matchtype match_type, long elapsed)
{
	/* Calculate component/vendor md5 for license and dependency query */
	uint8_t pair_md5[16]="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	component_vendor_md5(match.vendor, match.component, pair_md5);

	printf("    {\n");
	printf("      \"id\": \"%s\",\n", matchtypes[match_type]);
	printf("      \"elapsed\": \"%.6fs\",\n", (double) elapsed / 1000000);
	printf("      \"lines\": \"%s\",\n", match.lines);
	printf("      \"oss_lines\": \"%s\",\n", match.oss_lines);
	printf("      \"matched\": \"%s\",\n", match.matched);
	printf("      \"vendor\": \"%s\",\n", match.vendor);
	printf("      \"component\": \"%s\",\n", match.component);
	printf("      \"version\": \"%s\",\n", match.version);
	printf("      \"latest\": \"%s\",\n", match.latest_version);
	printf("      \"url\": \"%s\",\n", match.url);
	printf("      \"file\": \"%s\",\n", match.file);
	printf("      \"size\": \"%s\",\n", match.size);
	printf("      \"dependencies\": ");
	print_dependencies(pair_md5, true);
	printf("      \"licenses\": ");
	print_licenses(pair_md5, false);
	printf("    }\n");
	fflush(stdout);
}

void print_json_nomatch(char *md5_hex, long elapsed)
{
	printf("    {\n");
	printf("      \"id\": \"none\",\n");
	printf("      \"elapsed\": \"%.6fs\"\n", (double) elapsed / 1000000);
	printf("    }\n");
	fflush(stdout);
}

/* Output matches in JSON format via STDOUT */
void output_matches_json(match_data *matches, matchtype match_type, uint8_t *md5, char *filename, long elapsed)
{
	int match_counter = 0;
	char *md5_hex = bin_to_hex(md5, 16);

	flip_slashes(filename);

	/* Log slow query, if needed */
	slow_query_log(md5_hex, filename, elapsed);  

	/* Print comma separator */
	if (!first_file) printf("  ,\n");
	first_file = false;

	/* Print key (filename) */
	printf("  \"%s\": [\n", filename);

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

	printf("  ]\n");

	free(md5_hex);
}


