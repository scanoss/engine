// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/cyclonedx.c
 *
 * CycloneDX output handling
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>

#include "cyclonedx.h"
#include "limits.h"
#include "util.h"
#include "license.h"

static void print_serial_number()
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

void cyclonedx_open()
{
    printf("{\n");
    printf("  \"bomFormat\": \"CycloneDX\",\n");
    printf("  \"specVersion\": \"1.2\",\n");
    print_serial_number();
    printf("  \"version\": 1,\n");
    printf("  \"components\": [\n");
}

void cyclonedx_close()
{
    printf("  ]\n}\n");
}

void print_json_match_cyclonedx(int i)
{
    printf("    {\n");
    printf("      \"type\": \"library\",\n");
    printf("      \"name\": \"%s\",\n", component_list[i].component);
    printf("      \"publisher\": \"%s\",\n", component_list[i].vendor);

    if (strcmp(component_list[i].version, component_list[i].latest_version))
        printf("      \"version\": \"%s-%s\",\n", component_list[i].version, component_list[i].latest_version);
    else
        printf("      \"version\": \"%s\",\n", component_list[i].version);

		if (*component_list[i].license)
		{
			printf("      \"licenses\": [\n");
			printf("        {\n");
			printf("          \"license\": {\n");
			printf("             \"id\": \"%s\"\n", component_list[i].license);
			printf("          }\n");
			printf("        }\n");
			printf("      ],\n");
		}
		printf("      \"purl\": \"%s@%s\"\n", component_list[i].purl, component_list[i].version);
		printf("    }\n");
		fflush(stdout);
}

