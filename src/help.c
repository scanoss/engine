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

/**
  * @file help.c
  * @date 12 Jul 2020 
  * @brief Contains the help.
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/help.c
  */

#include "help.h"
#include "scanoss.h"
#include "limits.h"

/**
 * @brief Print the help
 */
void help ()
{
  printf ("ScanOSS Engine v%s\n", SCANOSS_VERSION);
  printf ("\n\
This program performs an OSS inventory scan of the specified TARGET by comparing it against the ScanOSS Knowledgebase.\n\
Results are displayed in JSON format through STDOUT.\n\
\n\
Syntax: scanoss [parameters] [TARGET]\n\
\n\
Configuration:\n\
-w         Process TARGET as a .wfp file, regardless of its actual extension.\n\
-H         Enable High Precision Snippet Match mode (requires 'libhpsm.so' in the system).\n\
-e         Match only files with identical extensions as the scanned file (default: off).\n\
-M NUMBER  Search for up to NUMBER different components in each file (maximum: 9).\n\
-T NUMBER  Set snippet scanning tolerance percentage (default: 0.1).\n\
-s SBOM    Include assets from a JSON SBOM file (CycloneDX/SPDX2.2 format) in identification.\n\
-b SBOM    Exclude matches from assets listed in JSON SBOM file (CycloneDX/SPDX2.2 format).\n\
-B SBOM    Same as \"-b\" but with forced snippet scanning.\n\
-a SBOM    Show attribution notices for the provided SBOM.json file.\n\
-c HINT    Add a component HINT to guide scan results.\n\
-k KEY     Show contents of the specified KEY file from MZ sources archive.\n\
-l LICENSE Display OSADL metadata for the given SPDX license ID.\n\
\n\
Options:\n\
-t  Run engine performance tests.\n\
-v  Show version information and exit.\n\
-n  Set database name (default: oss).\n\
-h  Display this help information and exit.\n\
-d  Store debugging information to disk (/tmp).\n\
-q  Suppress JSON output (show only debugging info via STDERR).\n\
\n\
Environment variables:\n\
SCANOSS_MATCHMAP_MAX: Set the snippet scanning match map size (default: %d).\n\
SCANOSS_FILE_CONTENTS_URL: Define the API URL endpoint for sources. Source url wont be reported if it's not defined.\n\
\n\
Engine scanning flags:\n\
Configure the scanning engine using flags with the -F parameter.\n\
These settings can also be specified in %s\n\
+-------+-------------------------------------------------------+\n\
| Flag  | Setting                                               |\n\
+-------+-------------------------------------------------------+\n\
|    1  | Disable snippet matching (default: enabled)           |\n\
|    2  | Enable snippet_ids (default: disabled)                |\n\
|    4  | Disable dependencies (default: enabled)               |\n\
|    8  | Disable licenses (default: enabled)                   |\n\
|   16  | Disable copyrights (default: enabled)                 |\n\
|   32  | Disable vulnerabilities (default: enabled)            |\n\
|   64  | Disable quality (default: enabled)                    |\n\
|  128  | Disable cryptography (default: enabled)               |\n\
|  256  | Disable best match only (default: enabled)            |\n\
|  512  | Hide identified files (default: disabled)             |\n\
| 1024  | Enable download_url (default: disabled)               |\n\
| 2048  | Enable \"use path hint\" logic (default: disabled)      |\n\
| 4096  | Disable extended server stats (default: enabled)      |\n\
| 8192  | Disable health layer (default: enabled)               |\n\
| 16384 | Enable high accuracy, slower scan (default: disabled) |\n\
+-------+-------------------------------------------------------+\n\
Example: scanoss -F 12 DIRECTORY (scan DIRECTORY without license and dependency data)\n\
\n\
Copyright (C) 2018-2022 SCANOSS.COM\n", DEFAULT_MATCHMAP_FILES, ENGINE_FLAGS_FILE);
}
