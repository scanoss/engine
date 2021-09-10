// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/main.c
 *
 * SCANOSS Inventory Scanner
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

#include "attributions.h"
#include "debug.h"
#include "debug.h"
#include "file.h"
#include "help.h"
#include "ignorelist.h"
#include "license.h"
#include "limits.h"
#include "mz.h"
#include "report.h"
#include "scan.h"
#include "scanoss.h"
#include "util.h"

struct ldb_table oss_url;
struct ldb_table oss_file;
struct ldb_table oss_wfp;
struct ldb_table oss_purl;
struct ldb_table oss_copyright;
struct ldb_table oss_quality;
struct ldb_table oss_vulnerability;
struct ldb_table oss_dependency;
struct ldb_table oss_license;
struct ldb_table oss_attribution;
struct ldb_table oss_cryptography;

/* File tracing -qi */
uint8_t trace_id[MD5_LEN];
bool trace_on;

/* Initialize tables for the DB name indicated (defaults to oss) */
void initialize_ldb_tables(char *name)
{
	char oss_db_name[MAX_ARGLN];

	if (name) strcpy(oss_db_name, name);
	else strcpy(oss_db_name, DEFAULT_OSS_DB_NAME);

	strcpy(oss_url.db, oss_db_name);
	strcpy(oss_url.table, "url");
	oss_url.key_ln = 16;
	oss_url.rec_ln = 0;
	oss_url.ts_ln = 2;
	oss_url.tmp = false;

	strcpy(oss_file.db, oss_db_name);
	strcpy(oss_file.table, "file");
	oss_file.key_ln = 16;
	oss_file.rec_ln = 0;
	oss_file.ts_ln = 2;
	oss_file.tmp = false;

	strcpy(oss_wfp.db, oss_db_name);
	strcpy(oss_wfp.table, "wfp");
	oss_wfp.key_ln = 4;
	oss_wfp.rec_ln = 18;
	oss_wfp.ts_ln = 2;
	oss_wfp.tmp = false;

	strcpy(oss_purl.db, oss_db_name);
	strcpy(oss_purl.table, "purl");
	oss_purl.key_ln = 16;
	oss_purl.rec_ln = 0;
	oss_purl.ts_ln = 2;
	oss_purl.tmp = false;

	strcpy(oss_copyright.db, oss_db_name);
	strcpy(oss_copyright.table, "copyright");
	oss_copyright.key_ln = 16;
	oss_copyright.rec_ln = 0;
	oss_copyright.ts_ln = 2;
	oss_copyright.tmp = false;

	strcpy(oss_quality.db, oss_db_name);
	strcpy(oss_quality.table, "quality");
	oss_quality.key_ln = 16;
	oss_quality.rec_ln = 0;
	oss_quality.ts_ln = 2;
	oss_quality.tmp = false;

	strcpy(oss_vulnerability.db, oss_db_name);
	strcpy(oss_vulnerability.table, "vulnerability");
	oss_vulnerability.key_ln = 16;
	oss_vulnerability.rec_ln = 0;
	oss_vulnerability.ts_ln = 2;
	oss_vulnerability.tmp = false;

	strcpy(oss_dependency.db, oss_db_name);
	strcpy(oss_dependency.table, "dependency");
	oss_dependency.key_ln = 16;
	oss_dependency.rec_ln = 0;
	oss_dependency.ts_ln = 2;
	oss_dependency.tmp = false;

	strcpy(oss_license.db, oss_db_name);
	strcpy(oss_license.table, "license");
	oss_license.key_ln = 16;
	oss_license.rec_ln = 0;
	oss_license.ts_ln = 2;
	oss_license.tmp = false;

	strcpy(oss_attribution.db, oss_db_name);
	strcpy(oss_attribution.table, "attribution");
	oss_attribution.key_ln = 16;
	oss_attribution.rec_ln = 0;
	oss_attribution.ts_ln = 2;
	oss_attribution.tmp = false;

	strcpy(oss_cryptography.db, oss_db_name);
	strcpy(oss_cryptography.table, "cryptography");
	oss_cryptography.key_ln = 16;
	oss_cryptography.rec_ln = 0;
	oss_cryptography.ts_ln = 2;
	oss_cryptography.tmp = false;
}

void recurse_directory(char *name)
{
	DIR *dir;
	struct dirent *entry;
	bool read = false;

	if (!(dir = opendir(name))) return;

	while ((entry = readdir(dir)))
	{
		if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;

		read = true;
		char *path =calloc (MAX_PATH, 1);
		sprintf (path, "%s/%s", name, entry->d_name);
			
		if (entry->d_type == DT_DIR)
				recurse_directory(path);

		else if (is_file(path))
		{

			/* Scan file directly */
			scan_data scan = scan_data_init(path);

			bool wfp = false;
			if (extension(path)) if (!strcmp(extension(path), "wfp")) wfp = true;

			if (wfp)
				wfp_scan(&scan);
			else
				ldb_scan(&scan);

			scan_data_free(scan);
		}

		free(path);
	}

	if (read) closedir(dir);
}

bool validate_alpha(char *txt)
{
	/* Check digits (and convert to lowercase) */
	for (int i = 0; i < strlen(txt); i++)
	{
		if (!isalnum(txt[i])) return false;
	}

	return true;
}

/* Read flags from /etc/scanoss_flags.cfg */
uint64_t read_flags()
{
	FILE *file = fopen(ENGINE_FLAGS_FILE, "rb");
	if (file)
	{
		char flags[MAX_ARGLN] = "0";
		fseek(file, 0, SEEK_END);
		int length = ftell(file);
		if (length <= MAX_ARGLN)
		{
			fseek(file, 0, SEEK_SET);
			fread(flags, 1, length, file);
		}
		fclose(file);
		return atol(flags);
	}
	return 0;
}

int main(int argc, char **argv)
{
	//global var initialization - it must be improved
	debug_on = false;
	quiet = false;

	/* File tracing with -qi */
	trace_on = false;
	memset(trace_id, 0 ,16);

	if (argc <= 1)
	{
		fprintf (stdout, "Missing parameters. Please use -h\n");
		exit(EXIT_FAILURE);
	}

	engine_flags = read_flags();

	bool force_wfp = false;

	microseconds_start = microseconds_now();

	*component_hint = 0;
	*vendor_hint = 0;

	initialize_ldb_tables(NULL);

	/* Parse arguments */
	int option;
	bool invalid_argument = false;

	while ((option = getopt(argc, argv, ":f:s:b:c:k:a:F:l:n:i:wtvhedq")) != -1)
	{
		/* Check valid alpha is entered */
		if (optarg)
		{
			if ((strlen(optarg) > MAX_ARGLN))
			{
				invalid_argument = true;
				break;
			}
		}

		switch (option)
		{
			case 's':
				sbom = parse_sbom(optarg, false);
				break;

			case 'b':
				ignored_assets = parse_sbom(optarg, true);
				break;

			case 'c':
				strcpy(component_hint, optarg);
				break;

			case 'k':
				mz_file_contents(optarg);
				exit(EXIT_SUCCESS);
				break;

			case 'a':
				exit(attribution_notices(optarg));
				break;

			case 'F':
				engine_flags = atol(optarg);
				break;

			case 'l':
				print_osadl_license_data(optarg);
				exit(EXIT_SUCCESS);
				break;

			case 'n':
				initialize_ldb_tables(optarg);
				break;

			case 'i':
				if (strlen(optarg) == (MD5_LEN * 2))
				{
					ldb_hex_to_bin(optarg, MD5_LEN * 2, trace_id);
					trace_on = true;
				}
				else fprintf(stderr, "Ignoring -i due to invalid length\n");
				break;

			case 'w':
				force_wfp = true;
				break;

			case 't':
				scan_benchmark();
				exit(EXIT_SUCCESS);
				break;

			case 'v':
				printf("scanoss-%s\n", SCANOSS_VERSION);
				exit(EXIT_SUCCESS);
				break;

			case 'h':
				help();
				exit(EXIT_SUCCESS);
				break;

			case 'e':
				match_extensions = true;
				break;

			case 'q':
				debug_on = true;
				quiet = true;
				scanlog("Quiet mode enabled. Displaying only debugging info via STDERR.\n");
				break;

			case 'd':
				debug_on = true;
				scanlog(""); // Log time stamp
				break;

			case ':':
				printf("Missing value for parameter\n");
				invalid_argument = true;
				break;

			case '?':
				printf("Unsupported option: %c\n", optopt);
				invalid_argument = true;
				break;
		}
		if (invalid_argument) break;
	}

	for (;optind < argc-1; optind++)
	{
		printf("Invalid argument: %s\n", argv[optind]);
		invalid_argument = true;
	}

	if (invalid_argument)
	{
		printf("Error parsing arguments\n");
		exit(EXIT_FAILURE);
	}

	/* Perform scan */
	else 
	{
		/* Validate target */
		char *arg_target = argv[argc-1];
		bool isfile = is_file(arg_target);
		bool isdir = is_dir(arg_target);
		bool ishash = !isdir && !isfile && valid_md5(arg_target);

		if (!isfile && !isdir && !ishash)
		{
			fprintf(stdout, "Cannot access target %s\n", arg_target);
			exit(EXIT_FAILURE);
		}

		char *target = calloc(MAX_ARGLN, 1);

		if (strlen(argv[argc-1]) >= MAX_ARGLN)
		{
			fprintf(stdout, "Target cannot exceed %d bytes\n", MAX_ARGLN);
			exit(EXIT_FAILURE);
		}

		/* Remove trailing backslashes from target (if any) */
		strcpy (target, argv[argc-1]);
		for (int i=strlen(target)-1; i>=0; i--) if (target[i]=='/') target[i]=0; else break;

		/* Init scan structure */
		scan_data scan = scan_data_init(target);

		/* Open main report structure */
		json_open();

		/* Scan directory */
		if (isdir) recurse_directory(target);

		/* Scan hash */
		else if (ishash) hash_scan(&scan);

		/* Scan file */
		else
		{

			bool wfp_extension = false;
			if (extension(target)) if (!strcmp(extension(target), "wfp")) wfp_extension = true;
				if (force_wfp) wfp_extension = true;

			/* Scan wfp file */
			if (wfp_extension) wfp_scan(&scan);

			/* Scan file directly */
			else ldb_scan(&scan);

		}

		/* Close main report structure */
		json_close();

		/* Free scan data */
		scan_data_free(scan);

		if (target) free (target);
	}

	if (sbom) free (sbom);
	if (ignored_assets)  free (ignored_assets);

	return EXIT_SUCCESS;
}
