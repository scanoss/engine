// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/osadl_metadata.c
 *
 * OSADL license metadata from
 * https://www.osadl.org/Access-to-raw-data.oss-compliance-raw-data-access.0.html 
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

const char *patent_hints[] = {"AFL-2.0", "AFL-2.1", "AGPL-3.0-only", \
"AGPL-3.0-or-later", "Apache-2.0", "BSD-2-Clause-Patent", "bzip2-1.0.5", \
"CC0-1.0", "CDDL-1.0", "CPL-1.0", "EPL-1.0", "EPL-2.0", "EUPL-1.1", "GPL-2.0-only", \
"GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "IBM-pibs", "IJG", "IPL-1.0", \
"LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later", "MPL-1.1", \
"MPL-2.0", "MPL-2.0-no-copyleft-exception", "MS-PL", "MS-RL", "OSL-3.0", "RPL-1.5", NULL};

const char *incompatibilities[] = {
"AGPL-3.0-only: Apache-1.0, Apache-1.1, BSD-4-Clause, BSD-4-Clause-UC, FTL, IJG, OpenSSL, Python-2.0, zlib-acknowledgement, XFree86-1.1",\
"AGPL-3.0-or-later: Apache-1.0, Apache-1.1, BSD-4-Clause, BSD-4-Clause-UC, FTL, IJG, OpenSSL, Python-2.0, zlib-acknowledgement, XFree86-1.1",\
"EUPL-1.1: Apache-1.0, Apache-1.1, BSD-4-Clause, BSD-4-Clause-UC, FTL, IJG, OpenSSL, Python-2.0, zlib-acknowledgement, XFree86-1.1",\
"GPL-2.0-only: Apache-1.0, Apache-1.1, Apache-2.0, BSD-4-Clause, BSD-4-Clause-UC, FTL, IJG, OpenSSL, Python-2.0, zlib-acknowledgement, XFree86-1.1",\
"GPL-2.0-or-later: Apache-1.0, Apache-1.1, Apache-2.0, BSD-4-Clause, BSD-4-Clause-UC, FTL, IJG, OpenSSL, Python-2.0, zlib-acknowledgement, XFree86-1.1",\
"GPL-3.0-only: Apache-1.0, Apache-1.1, BSD-4-Clause, BSD-4-Clause-UC, FTL, IJG, OpenSSL, Python-2.0, zlib-acknowledgement, XFree86-1.1",\
"GPL-3.0-or-later: Apache-1.0, Apache-1.1, BSD-4-Clause, BSD-4-Clause-UC, FTL, IJG, OpenSSL, Python-2.0, zlib-acknowledgement, XFree86-1.1",\
"LGPL-2.1-only: Apache-1.0, Apache-1.1, Apache-2.0, BSD-4-Clause, BSD-4-Clause-UC, FTL, IJG, OpenSSL, Python-2.0, zlib-acknowledgement, XFree86-1.1",\
"LGPL-2.1-or-later: Apache-1.0, Apache-1.1, Apache-2.0, BSD-4-Clause, BSD-4-Clause-UC, FTL, IJG, OpenSSL, Python-2.0, zlib-acknowledgement, XFree86-1.1",\
"LGPL-3.0-only: Apache-1.0, Apache-1.1, BSD-4-Clause, BSD-4-Clause-UC, FTL, IJG, OpenSSL, Python-2.0, zlib-acknowledgement, XFree86-1.1",\
"LGPL-3.0-or-later: Apache-1.0, Apache-1.1, BSD-4-Clause, BSD-4-Clause-UC, FTL, IJG, OpenSSL, Python-2.0, zlib-acknowledgement, XFree86-1.1", \
NULL};

