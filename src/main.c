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

#include "scanoss.h"
#include "scan.h"
#include "attributions.h"
#include "debug.h"
#include "blacklist.h"
#include "limits.h"
#include "debug.h"
#include "report.h"
#include "file.h"
#include "help.h"
#include "mz.h"
#include "license.h"

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

output_format set_format(char *arg)
{
	if (!strcmp(arg, "plain")) return plain;
	if (!strcmp(arg, "spdx")) return spdx;
	if (!strcmp(arg, "cyclonedx")) return cyclonedx;
	if (!strcmp(arg, "spdx_xml")) return spdx_xml;
	printf("Unsupported report format\n");
	exit(EXIT_FAILURE);
	return plain;
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

	if (argc <= 1)
	{
		fprintf (stdout, "Missing parameters. Please use -h\n");
		exit(EXIT_FAILURE);
	}

	engine_flags = read_flags();

	bool force_wfp = false;

	*component_hint = 0;
	*vendor_hint = 0;

	/* Initialise LDB tables */
	strcpy(oss_component.db, "oss");
	strcpy(oss_component.table, "url");
	oss_component.key_ln = 16;
	oss_component.rec_ln = 0;
	oss_component.ts_ln = 2;
	oss_component.tmp = false;

	strcpy(oss_file.db, "oss");
	strcpy(oss_file.table, "file");
	oss_file.key_ln = 16;
	oss_file.rec_ln = 0;
	oss_file.ts_ln = 2;
	oss_file.tmp = false;

	strcpy(oss_wfp.db, "oss");
	strcpy(oss_wfp.table, "wfp");
	oss_wfp.key_ln = 4;
	oss_wfp.rec_ln = 18;
	oss_wfp.ts_ln = 2;
	oss_wfp.tmp = false;

	/* Parse arguments */
	int option;
	bool invalid_argument = false;

	while ((option = getopt(argc, argv, ":f:s:b:c:k:a:F:l:wtvhedq")) != -1)
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
			case 'f':
				report_format = set_format(optarg);
				break;

			case 's':
				sbom = parse_sbom(optarg, false);
				break;

			case 'b':
				blacklisted_assets = parse_sbom(optarg, false);
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

		if (!isfile && !isdir)
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
		if (!(engine_flags & DISABLE_REPORT_OPEN_CLOSE))
			report_open(&scan);

		/* Scan directory */
		if (isdir) recurse_directory(target);

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
		if (!(engine_flags & DISABLE_REPORT_OPEN_CLOSE))
			report_close();
			
		/* Free scan data */
		scan_data_free(scan);

		if (target) free (target);
	}

	if (sbom) free (sbom);
	if (blacklisted_assets)  free (blacklisted_assets);

	return EXIT_SUCCESS;
}
