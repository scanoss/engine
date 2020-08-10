// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/report.c
 *
 * Output support in different formats
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


char *datestamp()
{
	time_t timestamp;
	struct tm *times;
	time(&timestamp);
	times = localtime(&timestamp);
	char *stamp = malloc(MAX_ARGLN);
	strftime(stamp, MAX_ARGLN, "%FT%T%z", times);
	return stamp;
}

void print_datestamp()
{
	char *stamp = datestamp();
	printf("      \"created\": \"%s\"\n", stamp);
	free(stamp);
}

void print_serial_number()
{
	/* Get hostname and time stamp */
	char *stamp = datestamp();
	char hostname[MAX_ARGLN] = "\0";
	gethostname(hostname, MAX_ARGLN - 1);
	strcat(stamp,hostname);

	/* Calculate serial number */
	uint8_t md5sum[16]="\0";
	MD5((uint8_t *) stamp, strlen(stamp), md5sum);
	char *md5hex = bin_to_hex(md5sum, 16);

	/* Print serial number */
	printf("  \"serialNumber\": \"scanoss:%s-%s\",\n",hostname, md5hex);

	free(stamp);
	free(md5hex);
}


/* Open JSON report */
void json_open()
{
	switch(json_format)
	{
		case plain:
			printf("{\n");
			break;

		case cyclonedx:
			printf("{\n");
			printf("  \"bomFormat\": \"CycloneDX\",\n");
			printf("  \"specVersion\": \"1.2\",\n");
			print_serial_number();
			printf("  \"version\": 1,\n");
			printf("  \"components\": [\n");
			break;

		case spdx:
			printf("{\n");
			printf("  \"Document\": {\n");
			printf("    \"specVersion\": \"SPDX-2.0\",\n");
			printf("    \"creationInfo\": {\n");
			printf("      \"creators\": [\n");
			printf("        \"Tool: SCANOSS Inventory Engine\",\n");
			printf("        \"Organization: http://scanoss.com\"\n");
			printf("      ],\n");
			printf("      \"comment\": \"This SPDX report has been automatically generated\",\n");
			printf("      \"licenseListVersion\": \"1.19\",\n");
			print_datestamp();
			printf("    },\n");
			printf("    \"spdxVersion\": \"SPDX-2.0\",\n");
			printf("    \"dataLicense\": \"CC0-1.0\",\n");
			printf("    \"id\": \"SPDXRef-DOCUMENT\",\n");
			printf("    \"name\": \"SPDX-Tools-v2.0\",\n");
			printf("    \"comment\": \"This document was automatically generated with SCANOSS.\",\n");
			printf("    \"externalDocumentRefs\": [],\n");
            printf("    \"documentDescribes\": [\n");
            printf("      {\n");
			break;
	}
}

/* Close JSON report */
void json_close()
{
	switch(json_format)
	{
		case plain:
			printf("}\n");
			break;

		case cyclonedx:
			printf("  ]\n}\n");
			break;

		case spdx:
			printf("      }\n");
			printf("    ]\n");
			printf("  }\n");
			printf("}\n");
			break;
	}
}
void json_open_file(char *filename)
{    
	switch(json_format)
	{
		case plain:
			printf("  \"%s\": [\n", filename);
			break;

		case cyclonedx:
			break;

		case spdx:
			break;
	}
}

void json_close_file()
{
	switch(json_format)
	{
		case plain:
			printf("  ]\n");
			break;

		case cyclonedx:
			break;

		case spdx:
			break;
	}
}

/* Trim string at first non-printable char */
void printable_only(char *text)
{
	for (int i = 0; i < strlen(text); i++)
		if (text[i] < '"' || text[i] > 'z') text[i] = 0;
}

void component_vendor_md5(char *component, char *vendor, uint8_t *out)
{
	char pair[1024] = "\0";
	if (strlen(component) + strlen(vendor) + 2 >= 1024) return;
	sprintf(pair, "%s/%s", component, vendor);
	MD5((uint8_t *)pair, strlen(pair), out);
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

void print_json_nomatch(char *md5_hex, long elapsed)
{
	printf("    {\n");
	printf("      \"id\": \"none\",\n");
	printf("      \"elapsed\": \"%.6fs\"\n", (double) elapsed / 1000000);
	printf("    }\n");
	fflush(stdout);
}

void print_json_match_plain(char *md5_hex, match_data match, matchtype match_type, long elapsed)
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

void print_json_match_cyclonedx(char *md5_hex, match_data match, matchtype match_type, long elapsed)
{
	printf("    {\n");
	printf("      \"type\": \"file\",\n");
	printf("      \"publisher\": \"%s\",\n", match.vendor);
	printf("      \"group\": \"%s\",\n", match.vendor);
	printf("      \"name\": \"%s\",\n", match.component);

	if (strcmp(match.version, match.latest_version))
		printf("      \"version\": \"%s-%s\",\n", match.version, match.latest_version);
	else
		printf("      \"version\": \"%s\",\n", match.version);

	printf("      \"hashes\": [\n");
	printf("        {\n");
	printf("          \"alg\": \"MD5\",\n");
	printf("          \"content\": \"%s\"\n", md5_hex);
	printf("        }\n");
	printf("      ],\n");
	printf("      \"licenses\": [],\n");

	if (strcmp(match.lines,"all"))
		printf("      \"purl\": \"%s#%s\",\n", match.url, match.file);
	else
		printf("      \"purl\": \"%s\",\n", match.url);

	printf("      \"description\": \"Lines matched: %s\"\n", match.lines);
	printf("    }\n");
	fflush(stdout);
}

void print_json_match_spdx(char *md5_hex, match_data match, matchtype match_type, long elapsed)
{
	printf("        \"Package\": {\n");
	printf("          \"name\": \"%s\",\n", match.component);

    if (strcmp(match.version, match.latest_version))
	{
        printf("          \"versionInfo\": \"%s-%s\",\n", match.version, match.latest_version);
	}
    else
	{
        printf("          \"versionInfo\": \"%s\",\n", match.version);
	}

	printf("          \"supplier\": \"%s\",\n", match.vendor);
	printf("          \"downloadLocation\": \"%s\",\n", match.url);
	printf("          \"checksum\": [\n");
	printf("            {\n");
	printf("              \"algorithm\": \"checksumAlgorithm_md5\",\n");
	printf("              \"value\": \"%s\"\n", md5_hex);
	printf("            }\n");
	printf("          ],\n");
	printf("          \"description\": \"Detected by SCANOSS Inventorying Engine.\",\n");
	printf("          \"licenseConcluded\": \"\",\n");
	printf("          \"licenseInfoFromFiles\": []\n");
	printf("        }\n");

	fflush(stdout);
}

void print_json_match(char *md5_hex, match_data match, matchtype match_type, long elapsed)
{
	switch(json_format)
	{

		case plain:
			print_json_match_plain(md5_hex, match, match_type, elapsed);
			break;

		case cyclonedx:
			print_json_match_cyclonedx(md5_hex, match, match_type, elapsed);
			break;

		case spdx:
			print_json_match_spdx(md5_hex, match, match_type, elapsed);
			break;
	}
}
