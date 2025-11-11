// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * inc/debug.h
 *
 * Debug and logging function declarations
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

#ifndef __DEBUG_H
    #define __DEBUG_H
    
#include <stdint.h>
#include <stdbool.h>
#include "scanoss.h"
#include "scan.h"

extern bool debug_on; //= false; //set debug mode from main.
extern bool quiet;


bool scanlog_init(void);
void scanlog(const char *fmt, ...);
void map_dump(scan_data_t *scan);
long microseconds_now(void);
void scan_benchmark(void);
void slow_query_log(scan_data_t *scan);
long microseconds_now(void);

#endif
