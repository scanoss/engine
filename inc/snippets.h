// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * inc/snippets.h
 *
 * Snippet matching function declarations
 *
 * Copyright (C) 2018-2021 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __SNIPPETS_H
    #define __SNIPPETS_H

#include "scanoss.h"
#include "match_list.h"
#include "scan.h"
#include "debug.h"
#include "util.h"

extern int matchmap_max_files;

bool skip_snippets(char *src, uint64_t srcln);
uint32_t compile_ranges(match_data_t * match);
void biggest_snippet(scan_data_t *scan);
void clear_hits(uint8_t *match);
#endif
