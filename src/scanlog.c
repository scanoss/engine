// SPDX-License-Identifier: GPL-2.0-or-later
/*
* src/scanlog.c
*
* Implements logging function
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
  @file scanlog.c
  @date 30 Sep 2025
  @brief Implements logging function

  Long description // TODO
  @see https://github.com/scanoss/engine/blob/master/src/scan.c
 */


#include "debug.h"

long microseconds_start;
bool debug_on; //= false; //set debug mode from main.
bool quiet;


/**
 * @brief //Calculate the time of execution
 * @return //time in ms  
 */
long microseconds_now()
{
	struct timeval now; gettimeofday(&now, NULL);
	return (now.tv_sec*(int)1e6+now.tv_usec);
}

/**
 * @brief Initialize the log file as blank
 * @return true if successful, false otherwise
 */
bool scanlog_init()
{
	FILE *log = fopen(SCAN_LOG, "w");
	if (!log)
	{
		fprintf(stderr, "Warning: Cannot create/initialize the log file\n");
		return false;
	}
	fclose(log);
	return true;
}

/**
 * @brief Print the logs in stderr
 * @param fmt string to be printed
 * @param ... //TODO
 */
void scanlog(const char *fmt, ...)
{
	if (!debug_on) return;

    va_list args;
    va_start(args, fmt);

	if (quiet)
	{
		if (*fmt)
		{
			fprintf(stderr, "%06ld ", microseconds_now() - microseconds_start);
			vfprintf(stderr, fmt, args);
		}
		return;
	}

	FILE *log = fopen(SCAN_LOG, "a");
	if (!log)
	{
		fprintf(stderr, "Warning: Cannot access the log file\n");
		return;
	}
	/* Add entry to log */
	if (*fmt) vfprintf(log, fmt, args);

	/* Log time stamp if fmt is empty */
	else
	{
		time_t now;
		time(&now);
		fprintf(log, "\n>>>>>> %s", ctime(&now));
	}

	fclose(log);
	va_end(args);
}