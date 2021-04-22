// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/license.c
 *
 * "License" data aggregation functions
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
#include <stdbool.h>
#include <stdint.h>

#include "limits.h"
#include "license.h"
#include "debug.h"
#include "util.h"
#include "parse.h"

const char *license_sources[] = {"component_declared", "file_spdx_tag", "file_header"};
const char *osadl_licenses[] = {"AFL-2.0", "AFL-2.1", "AGPL-3.0-only", \
"AGPL-3.0-or-later", "Apache-1.0", "Apache-1.1", "Apache-2.0", \
"Artistic-1.0-Perl", "BSD-2-Clause", "BSD-2-Clause-Patent", "BSD-3-Clause", \
"BSD-4-Clause", "BSD-4-Clause-UC", "BSL-1.0", "bzip2-1.0.5", "bzip2-1.0.6", \
"CC0-1.0", "CDDL-1.0", "CPL-1.0", "curl", "EFL-2.0", "EPL-1.0", "EPL-2.0", \
"EUPL-1.1", "FTL", "GPL-2.0-only", "Classpath-exception-2.0", "GPL-2.0-or-later",\
"GPL-3.0-only", "GPL-3.0-or-later", "HPND", "IBM-pibs", "ICU", "IJG", "IPL-1.0", \
"ISC", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later", \
"Libpng", "libtiff", "MirOS", "MIT", "MIT-CMU", "MPL-1.1", "MPL-2.0", \
"MPL-2.0-no-copyleft-exception", "MS-PL", "MS-RL", "NBPL-1.0", "NTP", "OpenSSL", \
"OSL-3.0", "Python-2.0", "Qhull", "RPL-1.5", "n.a.", "Unicode-DFS-2015", \
"Unicode-DFS-2016", "UPL-1.0", "WTFPL", "X11", "XFree86-1.1", "Zlib", \
"zlib-acknowledgement", NULL};
const char *copyleft_licenses[] = {"AGPL-3.0-only", "AGPL-3.0-or-later", "CDDL-1.0", \
"CPL-1.0", "EPL-1.0", "EPL-2.0", "EUPL-1.1", "GPL-2.0-only", "GPL-2.0-or-later", \
"GPL-3.0-only", "GPL-3.0-or-later", "IPL-1.0", "LGPL-2.1-only", "LGPL-2.1-or-later", \
"LGPL-3.0-only", "LGPL-3.0-or-later", "MPL-1.1", "MPL-2.0", \
"MPL-2.0-no-copyleft-exception", "MS-PL", "MS-RL", "OpenSSL", "OSL-3.0", \
"RPL-1.5", NULL};

/* Return true if license is in the osadl license list */
bool is_osadl_license(char *license)
{
	int i = 0;
	while (osadl_licenses[i])
	{
		if (!strcmp(license,osadl_licenses[i++])) return true;
	}
	return false;
}

/* Return true if license is copyleft */
bool is_copyleft(char *license)
{return true;
	int i = 0;
	while (copyleft_licenses[i])
	{
		if (!strcmp(license,copyleft_licenses[i++])) return true;
	}
	return false;
}

/* Output OSADL license metadata */
void oasdl_license_data(char *license)
{
	if (is_osadl_license(license))
	{
		printf("          \"obligations\": \"https://www.osadl.org/fileadmin/checklists/unreflicenses/%s.txt\",\n", license);
		if (is_copyleft(license))
			printf("          \"copyleft\": \"yes\",\n");
		else
			printf("          \"copyleft\": \"no\",\n");
	}
}


bool get_first_license_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *CSV = calloc(datalen + 1, 1);
	memcpy(CSV, (char *) data, datalen);

	extract_csv(ptr, CSV, 2, MAX_JSON_VALUE_LEN);
	free(CSV);

	return true;
}

bool print_licenses_item(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char *CSV  = calloc(datalen + 1, 1);
	memcpy(CSV, data, datalen);

	char *source  = calloc(MAX_JSON_VALUE_LEN, 1);
	char *license = calloc(MAX_JSON_VALUE_LEN, 1);

	extract_csv(source, CSV, 1, MAX_JSON_VALUE_LEN);
	extract_csv(license, CSV, 2, MAX_JSON_VALUE_LEN);
	free(CSV);

	int src = atoi(source);

	scanlog("Fetched license %s\n", license);
	printable_only(license);
	bool reported = false;

	if (*license && (src < (sizeof(license_sources) / sizeof(license_sources[0]))))
	{
		if (iteration) printf(",\n"); else printf("\n");
		printf("        {\n");
		printf("          \"name\": \"%s\",\n", license);
		oasdl_license_data(license);
		printf("          \"source\": \"%s\"\n", license_sources[atoi(source)]);
		printf("        }");
		reported = true;
	}

	free(source);
	free(license);

	return reported;
}

void get_license(match_data match, char *license)
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
		records = ldb_fetch_recordset(NULL, table, match.file_md5, false, get_first_license_item, license);
		if (!records)
			records = ldb_fetch_recordset(NULL, table, match.url_md5, false, get_first_license_item, license);
		if (!records)
			records = ldb_fetch_recordset(NULL, table, match.pair_md5, false, get_first_license_item, license);
	}
}

void print_licenses(match_data match)
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

	/* Print URL license */
	if (*match.license)
	{
		printf("        {\n");
		printf("          \"name\": \"%s\",\n", match.license);
		oasdl_license_data(match.license);
		printf("          \"source\": \"%s\"\n", license_sources[0]);
		printf("        }");
	}

	/* Look for component or file license */
	else if (ldb_table_exists("oss", "license"))
	{
		records = ldb_fetch_recordset(NULL, table, match.file_md5, false, print_licenses_item, NULL);
		if (records) scanlog("File license returns hits\n");
		if (!records)
		{
			records = ldb_fetch_recordset(NULL, table, match.url_md5, false, print_licenses_item, NULL);
			if (records) scanlog("Component license returns hits\n");
		}
		if (!records)
		{
			records = ldb_fetch_recordset(NULL, table, match.pair_md5, false, print_licenses_item, NULL);
			if (records) scanlog("Vendor/component license returns hits\n");
		}
	}

	if (records) printf("\n      ");
	printf("],\n");
}

