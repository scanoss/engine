// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/spdx.c
 *
 * SPDX output handling
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
#include "copyright.h"
#include "limits.h"
#include "spdx.h"
#include "util.h"
#include "license.h"

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

	printf("      \"created\": \"");
	print_datestamp();
	printf("\"\n");

	printf("    },\n");
	printf("    \"spdxVersion\": \"SPDX-2.0\",\n");
	printf("    \"dataLicense\": \"CC0-1.0\",\n");
	printf("    \"id\": \"SPDXRef-DOCUMENT\",\n");
	printf("    \"name\": \"SPDX-Tools-v2.0\",\n");
	printf("    \"comment\": \"This document was automatically generated with SCANOSS.\",\n");
	printf("    \"externalDocumentRefs\": [],\n");
	printf("    \"Packages\": [\n");
}

void spdx_close()
{
	printf("       ]\n");
	printf("      }\n");
	printf("}\n");
}

void print_json_match_spdx(int i)
{
	printf("         {\n");
	printf("          \"name\": \"%s\",\n", component_list[i].component);

	if (strcmp(component_list[i].version, component_list[i].latest_version))
	{
		printf("          \"versionInfo\": \"%s-%s\",\n", component_list[i].version, component_list[i].latest_version);
	}
	else
	{
		printf("          \"versionInfo\": \"%s\",\n", component_list[i].version);
	}

	printf("          \"supplier\": \"%s\",\n", component_list[i].vendor);
	printf("          \"downloadLocation\": \"%s\",\n", component_list[i].purl);
	printf("          \"description\": \"Detected by SCANOSS Inventorying Engine.\",\n");
	printf("          \"licenseConcluded\": \"\",\n");
	printf("          \"licenseInfoFromFiles\": \"%s\"\n", component_list[i].license);
	printf("         }\n");

	fflush(stdout);
}
