// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/cyclonedx.c
 *
 * CycloneDX output handling
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

void print_json_match_cyclonedx(scan_data scan, match_data match)
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
    char *md5 = md5_hex(scan.md5);
    printf("          \"content\": \"%s\"\n", md5);
    free(md5);
    printf("        }\n");
    printf("      ],\n");
    printf("      \"licenses\": [\n");
    printf("        {\n");
    printf("          \"license\": {\n");
    printf("             \"id\": \"");
    print_first_license(match);
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

