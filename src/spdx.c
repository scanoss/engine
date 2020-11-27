// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/spdx.c
 *
 * SPDX output handling
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

void spdx_open()
{
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
}

void spdx_close()
{
    printf("      }\n");
    printf("    ]\n");
    printf("  }\n");
    printf("}\n");
}

void print_json_match_spdx(scan_data scan, match_data match)
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
    print_first_license(match);
    printf("\"\n");
    printf("        }\n");

    fflush(stdout);
}
