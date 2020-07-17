// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/help.c
 *
 * Built-in help
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
-w       Treats TARGET as a .wfp file regardless of the actual file extension\n\
-s FILE  Use assets specified in the provided JSON SBOM (CycloneDX/SPDX2.2 JSON format) as input to identification\n\
-b FILE  Blacklist matches to assets specified in the provided JSON SBOM (CycloneDX/SPDX2.2 JSON format)\n\
\n\
Options:\n\
-t  Tests engine performance\n\
-v  Display version and exit\n\
-h  Display this help and exit\n\
-d  Enable debugging information\n\
\n\
Copyright (C) 2018-2020 ScanOSS LTD\n");
}
