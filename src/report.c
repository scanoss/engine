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

char *md5_hex(uint8_t *md5)
{
	char *out =  calloc(2 * MD5_LEN + 1, 1);
	for (int i = 0; i < MD5_LEN; i++) sprintf(out + strlen(out), "%02x", md5[i]);
	return out;
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
	char *md5hex = md5_hex(md5sum);

	/* Print serial number */
	printf("  \"serialNumber\": \"scanoss:%s-%s\",\n",hostname, md5hex);

	free(stamp);
	free(md5hex);
}


/* Open JSON report */
void json_open()
{
	if (quiet) return;

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
	if (quiet) return;

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
	if (quiet) return;

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
	if (quiet) return;

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
	for (int i = 0; i < strlen(pair); i++) pair[i] = tolower(pair[i]);
	MD5((uint8_t *)pair, strlen(pair), out);
}

bool print_first_license_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *license = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(license,(char *) data, 2, MAX_JSON_VALUE_LEN);
	printable_only(license);

	if (*license) printf(license);

	free(license);

	if (*license) return true;

	return false;
}

bool print_licenses_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *source  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *license = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(source, (char *) data, 1, MAX_JSON_VALUE_LEN);
	extract_csv(license,(char *) data, 2, MAX_JSON_VALUE_LEN);

	int src = atoi(source);

	printable_only(license);

	if (*license && (src <= (sizeof(license_sources) / sizeof(license_sources[0]))))
	{
		if (iteration) printf(",\n"); else printf("\n");
		printf("        {\n");
		printf("          \"name\": \"%s\",\n", license);
		printf("          \"source\": \"%s\"\n", license_sources[atoi(source)]);
		printf("        }");
	}

	free(source);
	free(license);

	return true;
}

/* Returns a pointer to the character following the first comma in "data" */
char *skip_first_comma(char *data)
{
    char *ptr = data;
    while (*ptr)
    {
        if (*ptr == ',') return ++ptr;
        ptr++;
    }
    return data;
}

bool get_first_copyright(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	if ((datalen + 1) >= MAX_COPYRIGHT) datalen = MAX_COPYRIGHT;
	data[datalen] = 0;
	strcpy(ptr, skip_first_comma((char *) data));
	return true;
}

void clean_copyright(char *out, char *copyright)
{
	int i;
	char byte[2] = "\0\0";

	for (i = 0; i < (MAX_COPYRIGHT - 1); i++)
	{
		*byte = copyright[i];
		if (!*byte) break;
		else if (isalnum(*byte)) out[i] = *byte; 
		else if (strstr(" @#^()[]-_+;:.<>",byte)) out[i] = *byte;
		else out[i] = '*';
	}
	out[i] = 0;
}

bool print_copyrights_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *source  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *copyright = calloc(MAX_COPYRIGHT, 1);

	extract_csv(source, (char *) data, 1, MAX_JSON_VALUE_LEN);
	clean_copyright(copyright, skip_first_comma((char *) data));

	int src = atoi(source);

	if (*copyright && (src <= (sizeof(copyright_sources) / sizeof(copyright_sources[0]))))
	{
		if (iteration) printf(",\n"); else printf("\n");
		printf("        {\n");
		printf("          \"name\": \"%s\",\n", copyright);
		printf("          \"source\": \"%s\"\n", copyright_sources[atoi(source)]);
		printf("        }");
	}

	free(source);
	free(copyright);

	return false;
}


void print_first_license(uint8_t *pair, match_data match)
{
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
	{
		records = ldb_fetch_recordset(NULL, table, match.file_md5, false, print_first_license_item, NULL);
		if (!records)
			records = ldb_fetch_recordset(NULL, table, match.component_md5, false, print_first_license_item, NULL);
		if (!records)
			records = ldb_fetch_recordset(NULL, table, pair, false, print_first_license_item, NULL);
	}
}

void print_licenses(uint8_t *pair, match_data match)
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
	{
		records = ldb_fetch_recordset(NULL, table, match.file_md5, false, print_licenses_item, NULL);
		if (records) scanlog("File license returns hits\n");
		if (!records)
		{
			records = ldb_fetch_recordset(NULL, table, match.component_md5, false, print_licenses_item, NULL);
			if (records) scanlog("Component license returns hits\n");
		}
		if (!records)
		{
			records = ldb_fetch_recordset(NULL, table, pair, false, print_licenses_item, NULL);
			if (records) scanlog("Vendor/component license returns hits\n");
		}
	}

	if (records) printf("\n      ");
	printf("],\n");
}

void get_copyright(match_data match, char *copyright)
{
	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "copyright");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	if (ldb_table_exists("oss", "copyright"))
		ldb_fetch_recordset(NULL, table, match.file_md5, false, get_first_copyright, copyright);
}

void print_copyrights(uint8_t *pair, match_data match)
{
	printf("[");

	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "copyright");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	uint32_t records = 0;

	if (ldb_table_exists("oss", "copyright"))
	{
		records = ldb_fetch_recordset(NULL, table, match.file_md5, false, print_copyrights_item, NULL);
		if (!records)
			records = ldb_fetch_recordset(NULL, table, match.component_md5, false, print_copyrights_item, NULL);
		if (!records)
			records = ldb_fetch_recordset(NULL, table, pair, false, print_copyrights_item, NULL);
	}

	if (records) printf("\n      ");
	printf("],\n");
}

bool print_vulnerability_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *source  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *introduced = calloc(MAX_JSON_VALUE_LEN, 1);
	char *patched = calloc(MAX_JSON_VALUE_LEN, 1);
	char *CVE  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *ID  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *severity = calloc(MAX_JSON_VALUE_LEN, 1);
	char *date = calloc(MAX_JSON_VALUE_LEN, 1);
	char *summary = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(source, (char *) data, 1, MAX_JSON_VALUE_LEN);
	extract_csv(introduced, (char *) data, 3, MAX_JSON_VALUE_LEN);
	extract_csv(patched, (char *) data, 4, MAX_JSON_VALUE_LEN);
	extract_csv(CVE, (char *) data, 5, MAX_JSON_VALUE_LEN);
	extract_csv(ID, (char *) data, 6, MAX_JSON_VALUE_LEN);
	extract_csv(severity, (char *) data, 7, MAX_JSON_VALUE_LEN);
	extract_csv(date, (char *) data, 8, MAX_JSON_VALUE_LEN);
	extract_csv(summary, (char *) data, 9, MAX_JSON_VALUE_LEN);

	int src = atoi(source);

	if (*ID && (src <= (sizeof(vulnerability_sources) / sizeof(vulnerability_sources[0]))))
	{
		if (iteration) printf(",\n"); else printf("\n");
		printf("        {\n");
		printf("          \"ID\": \"%s\",\n", ID);
		printf("          \"CVE\": \"%s\",\n", CVE);
		printf("          \"severity\": \"%s\",\n", severity);
		printf("          \"reported\": \"%s\",\n", date);
		printf("          \"introduced\": \"%s\",\n", introduced);
		printf("          \"patched\": \"%s\",\n", patched);
		printf("          \"summary\": \"%s\",\n", summary);
		printf("          \"source\": \"%s\"\n", vulnerability_sources[src]);
		printf("        }");
	}

	free(source);
	free(introduced);
	free(patched);
	free(CVE);
	free(ID);
	free(severity);
	free(date);
	free(summary);

	return false;
}

void print_vulnerabilities(uint8_t *pair, match_data match)
{
	printf("[");

	/* Open sector */
	struct ldb_table table;
	strcpy(table.db, "oss");
	strcpy(table.table, "vulnerability");
	table.key_ln = 16;
	table.rec_ln = 0;
	table.ts_ln = 2;
	table.tmp = false;

	uint32_t records = 0;

	if (ldb_table_exists("oss", "vulnerability"))
	{
		records = ldb_fetch_recordset(NULL, table, pair, false, print_vulnerability_item, NULL);
	}

	if (records) printf("\n      ");
	printf("],\n");
}


bool print_dependencies_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *source = calloc(MAX_JSON_VALUE_LEN, 1);
	char *type   = calloc(MAX_JSON_VALUE_LEN, 1);
	char *dep    = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(source, (char *) data, 1, MAX_JSON_VALUE_LEN);
	extract_csv(type,   (char *) data, 2, MAX_JSON_VALUE_LEN);
	extract_csv(dep,    (char *) data, 3, MAX_JSON_VALUE_LEN);

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

void print_dependencies(uint8_t *pair, uint8_t *key)
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
	{
		records = ldb_fetch_recordset(NULL, table, key, false, print_dependencies_item, NULL);
		if (!records) 
			records = ldb_fetch_recordset(NULL, table, pair, false, print_dependencies_item, NULL);
	}

	if (records) printf("\n      ");
	printf("],\n");
}

void print_json_nomatch(scan_data scan)
{
	if (quiet) return;

	double elapsed = (microseconds_now() - scan.timer);
	printf("    {\n");
	printf("      \"id\": \"none\",\n");
	printf("      \"elapsed\": \"%.6fs\"\n", elapsed / 1000000);
	printf("    }\n");
	fflush(stdout);
}

void print_json_match_plain(scan_data scan, match_data match)
{
	/* Calculate component/vendor md5 for license and dependency query */
	uint8_t pair_md5[16]="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	component_vendor_md5(match.vendor, match.component, pair_md5);

	printf("    {\n");
	printf("      \"id\": \"%s\",\n", matchtypes[match.type]);
	printf("      \"lines\": \"%s\",\n", match.lines);
	printf("      \"oss_lines\": \"%s\",\n", match.oss_lines);
	printf("      \"matched\": \"%s\",\n", match.matched);
	printf("      \"vendor\": \"%s\",\n", match.vendor);
	printf("      \"component\": \"%s\",\n", match.component);
	printf("      \"version\": \"%s\",\n", match.version);
	printf("      \"latest\": \"%s\",\n", match.latest_version);

	if (debug_on)
	{
		char *component_id = md5_hex(match.component_md5);
		printf("      \"component_id\": \"%s\",\n", component_id);
		free(component_id);

		char *file_id = md5_hex(match.file_md5);
		printf("      \"file_id\": \"%s\",\n", file_id);
		free(file_id);
	}

	printf("      \"url\": \"%s\",\n", match.url);
	printf("      \"file\": \"%s\",\n", match.file);

	char *md5 = md5_hex(scan.md5);
	printf("      \"md5\": \"%s\",\n", md5);
	free(md5);

	printf("      \"dependencies\": ");
	print_dependencies(pair_md5, match.component_md5);
	printf("      \"licenses\": ");
	print_licenses(pair_md5, match);
	printf("      \"copyrights\": ");
	print_copyrights(pair_md5, match);
	printf("      \"vulnerabilities\": ");
	print_vulnerabilities(pair_md5, match);

	double elapsed = microseconds_now() - scan.timer;
	printf("      \"elapsed\": \"%.6fs\"\n", elapsed / 1000000);

	printf("    }\n");
	fflush(stdout);
}

void print_json_match_cyclonedx(scan_data scan, match_data match)
{
	/* Calculate component/vendor md5 for license and dependency query */
	uint8_t pair_md5[16]="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	component_vendor_md5(match.vendor, match.component, pair_md5);

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
	char *md5 = md5_hex(scan.md5);
	printf("          \"content\": \"%s\"\n", md5);
	free(md5);
	printf("        }\n");
	printf("      ],\n");
	printf("      \"licenses\": [\n");
	printf("        {\n");
	printf("          \"license\": {\n");
    printf("             \"id\": \"");
	print_first_license(pair_md5, match);
	printf("\"\n");
	printf("          }\n");
	printf("        }\n");
	printf("      ],\n");

	if (strcmp(match.lines,"all"))
		printf("      \"purl\": \"%s#%s\",\n", match.url, match.file);
	else
		printf("      \"purl\": \"%s\",\n", match.url);

	printf("      \"description\": \"Lines matched: %s\"\n", match.lines);
	printf("    }\n");
	fflush(stdout);
}

void print_json_match_spdx(scan_data scan, match_data match)
{
	/* Calculate component/vendor md5 for license and dependency query */
	uint8_t pair_md5[16]="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	component_vendor_md5(match.vendor, match.component, pair_md5);

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
	char copyright[MAX_COPYRIGHT];
	get_copyright(match, copyright);
	printf("          \"copyrightText\": \"%s\",\n", copyright);
	printf("          \"downloadLocation\": \"%s\",\n", match.url);
	printf("          \"checksum\": [\n");
	printf("            {\n");
	printf("              \"algorithm\": \"checksumAlgorithm_md5\",\n");

	char *md5 = md5_hex(scan.md5);
	printf("              \"value\": \"%s\"\n", md5);
	free(md5);

	printf("            }\n");
	printf("          ],\n");
	printf("          \"description\": \"Detected by SCANOSS Inventorying Engine.\",\n");
	printf("          \"licenseConcluded\": \"\",\n");
	printf("          \"licenseInfoFromFiles\": \"");
	print_first_license(pair_md5, match);
	printf("\"\n");
	printf("        }\n");

	fflush(stdout);
}

void print_json_match(scan_data scan, match_data match)
{
	if (quiet) return;

	switch(json_format)
	{

		case plain:
			print_json_match_plain(scan, match);
			break;

		case cyclonedx:
			print_json_match_cyclonedx(scan, match);
			break;

		case spdx:
			print_json_match_spdx(scan, match);
			break;
	}
}
