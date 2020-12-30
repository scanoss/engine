// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/debug.c
 *
 * Debugging-related subroutines
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
#include <stdio.h>
#include <sys/time.h>
#include "scanoss.h"
#include "limits.h"
#include "debug.h"
#include "scan.h"

double progress_timer = 0;

long microseconds_now()
{
	struct timeval now; gettimeofday(&now, NULL);
	return (now.tv_sec*(int)1e6+now.tv_usec);
}

void scanlog(const char *fmt, ...)
{
	if (!debug_on) return;

    va_list args;
    va_start(args, fmt);

	if (quiet)
	{
		if (*fmt) vfprintf(stderr, fmt, args);
		return;
	}

	FILE *log = fopen(SCAN_LOG, "a");

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

void progress(char *prompt, size_t count, size_t max, bool percent)
{
	struct timeval t;
	gettimeofday(&t, NULL);
	double tmp = (double)(t.tv_usec) / 1000000 + (double)(t.tv_sec);
	if ((tmp - progress_timer) < 1)
		return;
	progress_timer = tmp;

	if (percent)
		printf("%s%.2f%%\r", prompt, ((double)count / (double)max) * 100);
	else
		printf("%s%lu\r", prompt, count);
	fflush(stdout);
}

void slow_query_log(scan_data scan)
{
	long elapsed = microseconds_now() - scan.timer;
	if (elapsed > SLOW_QUERY_LIMIT_IN_USEC)
	{
		scanlog("SLOW QUERY!\n");
		char data[1024] = "\0";
		sprintf(data, "%lu, %.6fs, %s\n", (unsigned long)time(NULL), (double) elapsed / 1000000, scan.file_path);
		FILE *log = fopen(SLOW_QUERY_LOG, "a");
		if (!fprintf(log, data)) printf("Warning: Cannot log slow query\n");
		fclose(log);
	}
}

/* Output matchmap to a file (MAP_DUMP) */
void map_dump(scan_data *scan)
{
	FILE *map = fopen(MAP_DUMP, "w");

	/* Output column names */
	fprintf(map, "[MATCHING MD5                  ] HITS ");
	for (int j = 0; j < MATCHMAP_RANGES; j ++)
	{
		fprintf(map, "[   RANGE%02d  ] ", j);
	}
	fprintf(map, "[LASTWFP]\n");

	/* Output data rows */
	for (long i = 0; i < scan->matchmap_size; i++) {
		
		/* Print matching MD5 */
		uint8_t *md5 = scan->matchmap[i].md5;
		for (int j = 0; j < MD5_LEN; j++) fprintf(map, "%02x", md5[j]);

		/* Print hits */
		fprintf(map, " %04x ", scan->matchmap[i].hits);

		/* Print ranges */
		for (int j = 0; j < MATCHMAP_RANGES; j ++)
		{
			matchmap_range *range = &scan->matchmap[i].range[j];
			fprintf(map, "%04x-%04x<%04x ", range->from, range->to, range->oss_line);
		}

		/* Print last wfp */
		uint8_t *lwfp = scan->matchmap[i].lastwfp;
		fprintf(map, "%02x%02x%02x%02x\n", lwfp[0], lwfp[1], lwfp[2], lwfp[3]);
	}
	fclose(map);
}

void scan_benchmark()
{
	uint32_t total_hashes = 100; // Number of hashes per pseudo file
	uint32_t total_files = 100; // Number of pseudo hashes to scan
	double elapsed = microseconds_now();

	/* Init random number generator */
	time_t t;
	srand((unsigned) time(&t));

	for (int f = 0; f < total_files ; f++)
	{
		scan_data scan = scan_data_init("");
		scan.preload = true;
		memcpy(scan.md5, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", MD5_LEN);
		strcpy(scan.file_path, "pseudo_file");
		strcpy(scan.file_size, "1024");

		progress ("Scanning: ", f + 1, total_files, false);

		/* Fill up pseudo snippet hashes */
		for (uint32_t i = 0; i < total_hashes; i++)
		{
			scan.lines[i] = i;
			scan.hashes[i] = rand() % 256 + (rand() % 256) * 256 + (rand() % 256) * 256 * 256 + (rand() % 256) * 256 * 256 * 256;
		}
		scan.hash_count = total_hashes;

		ldb_scan_snippets(&scan);
		scan_data_free(scan);
	}
	printf("Analysis complete\n");

	/* Calculate elapsed time */
	int elapsed_ms = (microseconds_now() - elapsed) / 1000;

	printf ("Test executed in %dms\n", elapsed_ms);
	printf ("Average file scanning time is %dms\n", elapsed_ms / total_files);
	printf ("Performance is %d fingerprints per second\n", (total_files * total_hashes * 1000) / elapsed_ms);

}


