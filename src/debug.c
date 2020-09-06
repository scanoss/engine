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

double progress_timer = 0;

void scanlog(const char *fmt, ...)
{
	if (!debug_on) return;

    va_list args;
    va_start(args, fmt);
	FILE *log = fopen(SCAN_LOG, "a");

	/* Add entry to log */
	if (*fmt) vfprintf(log, fmt, args);

	/* Log time stamp if fmt is empty */
	else
	{
		time_t now;
		time(&now);
		fprintf(log, ">>> %s", ctime(&now));
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

void slow_query_log(char *md5_hex, char *filename, long elapsed)
{
	if (elapsed > SLOW_QUERY_LIMIT_IN_USEC)
	{
		scanlog("SLOW QUERY!\n");
		char data[1024] = "\0";
		sprintf(data, "%lu, %.6fs, %s\n", (unsigned long)time(NULL), (double) elapsed / 1000000, filename);
		FILE *log = fopen(SLOW_QUERY_LOG, "a");
		if (!fprintf(log, data)) printf("Warning: Cannot log slow query\n");
		fclose(log);
	}
}

long elapsed_time(struct timeval start)
{
	struct timeval end; gettimeofday(&end, NULL);
	return (end.tv_sec*(int)1e6+end.tv_usec) - (start.tv_sec*(int)1e6+start.tv_usec);
}

long microseconds_now()
{
	struct timeval now; gettimeofday(&now, NULL);
	return (now.tv_sec*(int)1e6+now.tv_usec);
}

void hexdump(FILE *map, uint8_t *in, uint64_t len, char *text, bool lf, uint32_t cut) 
{
	uint8_t *out = malloc (len*3+1);
	uint64_t c=0;
	uint64_t i;
	uint64_t p=0;
	uint32_t hi,lo;
	uint8_t hex[] = "0123456789abcdef";
	for (i=0; i<len; i++) 
	{
		hi = (in[i] & 0xF0) >> 4;
		lo = (in[i] & 0x0F);
		out[p++] = hex[hi];
		out[p++] = hex[lo];
		if (++c == cut && cut > 0) {
			out[p++] = 10;
			c = 0;
		}
	}
	out[p] = 0;
	fprintf (map, "%s%s", text, out);
	if (lf) fprintf(map, "\n");

	free (out);
}

void map_dump(uint8_t *mmap, uint64_t mmap_ptr) 
{
	FILE *map = fopen(MAP_DUMP, "w");
	fprintf(map, "[MATCHING MD5                  ] HITS [   RANGE0   ] [   RANGE1   ] [   RANGE2   ] [   RANGE3   ] [   RANGE4   ] [   RANGE5   ] [   RANGE6   ] [   RANGE7   ] [   RANGE8   ] [   RANGE9   ] [LASTWFP]\n");
	for (long i = 0; i<mmap_ptr; i++) {
		
		/* Print matching MD5 */
		hexdump (map, mmap+i*map_rec_len,    16 , "", false, 0);

		/* Print hits */
		hexdump (map, mmap+i*map_rec_len+16,  2 , " ", false, 0);

		/* Print ranges */
		for (int j = 18; j <= 72; j += 6)
		{
			hexdump(map, mmap + i * map_rec_len + j,  2 , " ", false, 0);
			fprintf(map, "-");
			hexdump(map, mmap + i * map_rec_len + j + 1,  2 , "", false, 0);
			fprintf(map, "<");
			hexdump(map, mmap + i * map_rec_len + j + 2,  2 , "", false, 0);
		}

		/* Print last wfp */
		hexdump (map, mmap+i*map_rec_len+78,  4 , " ", true, 0);
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
		scan_data scan = scan_data_init();
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


