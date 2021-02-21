// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/help.c
 *
 * Built-in help
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
#include "help.h"
#include "scanoss.h"

char SCANOSS_VERSION[7] = "4.1.2";

void help ()
{
	printf ("ScanOSS Engine v%s\n", SCANOSS_VERSION);
	printf ("\n\
This program performs an OSS inventory for the given TARGET comparing against the ScanOSS Knowledgebase. \
Results are printed in STDOUT in JSON format\n\
\n\
Syntax: scanoss [parameters] [TARGET]\n\
\n\
Configuration:\n\
-w         Treats TARGET as a .wfp file regardless of the actual file extension\n\
-e         Expect matching extensions to equal the file extension being scanned (default: off)\n\
-s SBOM    Use assets specified in the provided JSON SBOM (CycloneDX/SPDX2.2 JSON format) as input to identification\n\
-b SBOM    Blacklist matches to assets specified in the provided JSON SBOM (CycloneDX/SPDX2.2 JSON format)\n\
-a SBOM    Displays attribution notices for provided SBOM.json\n\
-f FORMAT  Set output format as: plain(default)|spdx|cyclonedx|spdx_xml\n\
-c HINT    Provide a component HINT to influence scan results\n\
-k KEY     Displays contents of file KEY from MZ sources archive\n\
\n\
Options:\n\
-t  Tests engine performance\n\
-v  Display version and exit\n\
-h  Display this help and exit\n\
-d  Save debugging information to disk (/tmp)\n\
-q  Produces no JSON output. Only debugging info via STDERR\n\
\n\
Copyright (C) 2018-2021 SCANOSS.COM\n");
}
