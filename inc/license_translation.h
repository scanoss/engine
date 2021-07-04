// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/license_translation.c
 *
 * Contains rules for translating license names into valid SPDX identifiers
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

#include <stddef.h>

const char *license_normalization[] = {
"AGPL-3.0-only,APL-3.0",
"AGPL-3.0-or-later,AGPL-3.0+",
"GPL-1.0-only,GPL-1.0","GPLv1",
"GPL-1.0-or-later,GPL-1.0+,GPLv1+",
"GPL-2.0-only,GPL-2.0,GPLv2",
"GPL-2.0-or-later,GPL-2.0+,GPLv2+",
"GPL-3.0-only,GPL-3.0,GPLv3",
"GPL-3.0-or-later,GPL-3.0+,GPLv3+",
"LGPL-2.1-only,LGPL-2.1",
"LGPL-2.1-or-later,LGPL-2.1+",
"LGPL-3.0-only,LGPL-3.0",
"LGPL-3.0-or-later,LGPL-3.0+",
NULL};
