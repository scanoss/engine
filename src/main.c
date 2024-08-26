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

/**
  * @file main.c
  * @date 12 Jul 2020 
  * @brief Starts the program execution
  
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/main.c
  */
 
#include "attributions.h"
#include "debug.h"
#include "file.h"
#include "help.h"
#include "ignorelist.h"
#include "license.h"
#include "limits.h"
#include "mz.h"
#include "parse.h"
#include "report.h"
#include "scan.h"
#include "scanoss.h"
#include "util.h"

#include <decrypt.h>
#include "hpsm.h"
#include <dlfcn.h>

struct ldb_table oss_url;
struct ldb_table oss_file;
struct ldb_table oss_path;
struct ldb_table oss_wfp;
struct ldb_table oss_purl;
struct ldb_table oss_copyright;
struct ldb_table oss_quality;
struct ldb_table oss_vulnerability;
struct ldb_table oss_dependency;
struct ldb_table oss_license;
struct ldb_table oss_attribution;
struct ldb_table oss_cryptography;
struct ldb_table oss_sources;
struct ldb_table oss_notices;
component_item *ignore_components;
component_item *declared_components;

bool lib_encoder_present = false;
#define LDB_VER_MIN "4.1.0"

void * lib_encoder_handle = NULL;
bool lib_encoder_load()
{
#ifndef SCANOSS_ENCODER_VERSION
	/*set decode funtion pointer to NULL*/
	lib_encoder_handle = dlopen("libscanoss_encoder.so", RTLD_NOW);
	char * err;
	if ((err = dlerror())) 
	{
		scanlog("Lib scanoss-encoder was not detected. %s\n", err);
	}
    
	if (lib_encoder_handle) 
	{
		scanlog("Lib scanoss-encoder present\n");
		decrypt_data = dlsym(lib_encoder_handle, "scanoss_decode_table");
		decrypt_mz = dlsym(lib_encoder_handle, "scanoss_decode_mz");
		encoder_version = dlsym(lib_encoder_handle, "scanoss_encoder_version");
		if ((err = dlerror())) 
		{
			printf("%s - You may need to update libscanoss_encoder.so\n", err);
			exit(EXIT_FAILURE);
		}

		char version[32] = "\0";
		encoder_version(version);
		scanlog("Lib scanoss-encoder version %s\n", version);
		return true;
    }
	decrypt_data = standalone_decrypt_data;
	decrypt_mz = NULL;
	return false;
#else
	decrypt_data = scanoss_decode_table;
	decrypt_mz = scanoss_decode_mz;
	encoder_version = scanoss_encoder_version;
	scanlog("Using built-in encoder library v%s\n", SCANOSS_ENCODER_VERSION);
	return false;
#endif
}

/* Initialize tables for the DB name indicated (defaults to oss) */
void initialize_ldb_tables(char *name)
{
	
	char * ldb_ver = NULL;
	ldb_version(&ldb_ver);
	scanlog("ldb version: %s\n", ldb_ver);
	
	if (!ldb_ver || strcmp(ldb_ver, LDB_VER_MIN) < 0)
	{
		fprintf(stderr, "The current ldb version %s is too old, please upgrade to %s to proceed\n", ldb_ver, LDB_VER_MIN);
		exit(EXIT_FAILURE);
	}
	free(ldb_ver);
	
	char oss_db_name[MAX_ARGLN];

	if (name) strcpy(oss_db_name, name);
	else strcpy(oss_db_name, DEFAULT_OSS_DB_NAME);

	char dbtable[MAX_ARGLN * 2];
	scanlog("Loading tables definitions\n");
	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "url");
	oss_url = ldb_read_cfg(dbtable);

	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "file");
	oss_file = ldb_read_cfg(dbtable);

	ldb_hash_mode_select(oss_file.key_ln);

	if (ldb_table_exists(oss_db_name, "path"))
	{
		path_table_present = true;
		snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "path");
		oss_path = ldb_read_cfg(dbtable);
	}

	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "wfp");
	oss_wfp = ldb_read_cfg(dbtable);

	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "purl");
	oss_purl = ldb_read_cfg(dbtable);

	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "copyright");
	oss_copyright = ldb_read_cfg(dbtable);
	
	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "quality");
	oss_quality = ldb_read_cfg(dbtable);

	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "vulnerability");
	oss_vulnerability = ldb_read_cfg(dbtable);

	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "dependency");
	oss_dependency = ldb_read_cfg(dbtable);

	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "license");
	oss_license = ldb_read_cfg(dbtable);

	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "attribution");
	oss_attribution = ldb_read_cfg(dbtable);

	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "cryptography");
	oss_cryptography = ldb_read_cfg(dbtable);

	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "sources");
	oss_sources = ldb_read_cfg(dbtable);

	snprintf(dbtable, MAX_ARGLN * 2, "%s/%s", oss_db_name, "notices");
	oss_notices = ldb_read_cfg(dbtable);

	kb_version_get();
	osadl_load_file();

	lib_encoder_present = lib_encoder_load();
}

/**
 * @brief  Read a direactory recursively
 * @param name path of the directory to be read
 */
int scan_max_snippets = SCAN_MAX_SNIPPETS_DEFAULT;
int scan_max_components = SCAN_MAX_COMPONENTS_DEFAULT;

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
			bool wfp = false;
			if (extension(path)) if (!strcmp(extension(path), "wfp")) wfp = true;
		
			if (wfp)
				wfp_scan(path, scan_max_snippets, scan_max_components);
			else
			{
				scan_data_t * scan = scan_data_init(path, scan_max_snippets, scan_max_components);
				ldb_scan(scan);
			}

		}

		free(path);
	}

	if (read) closedir(dir);
}

/**
 * @brief  check if string has an alphanumeric character
 * @param txt string to be analized 
 * @return true if string has an alphanumeric characters. false otherwise
 */
bool validate_alpha(char *txt)
{
	/* Check digits (and convert to lowercase) */
	for (int i = 0; i < strlen(txt); i++)
	{
		if (!isalnum(txt[i])) return false;
	}

	return true;
}

/**
 * @brief Read flags from /etc/scanoss_flags.cfg
 * @return //TODO
 */
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

/**
 * @brief //TODO
 * @param argc //TODO
 * @param argv //TODO
 * @return //TODO
 */
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
	int engine_flags_cmd_line = 0;

	bool force_wfp = false;
	bool force_bfp = false;
	
	microseconds_start = microseconds_now();

	/* Parse arguments */
	int option;
	bool invalid_argument = false;
	char * ldb_db_name = NULL;
	while ((option = getopt(argc, argv, ":f:s:b:B:c:k:a:F:l:n:M:N:wtvhedqH")) != -1)
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
				if (declared_components) printf("Cannot combine -s and -a\n");
				declared_components = get_components(optarg);
				engine_flags|= ENABLE_HIGH_ACCURACY; //high accuracy is necessary in this mode
				break;

			case 'b':
				ignore_components = get_components(optarg);
				break;

			case 'c':
				component_hint = strdup(optarg);
				break;

			case 'k':
				initialize_ldb_tables(ldb_db_name);
				mz_get_key(oss_sources, optarg);
				exit(EXIT_SUCCESS);
				break;

			case 'a':
				if (declared_components) 
				{
					printf("Cannot combine -s and -a\n");
					break;
				}
				initialize_ldb_tables(ldb_db_name);
				exit(attribution_notices(optarg));
				break;

			case 'F':
				engine_flags_cmd_line = atol(optarg);
				engine_flags |= engine_flags_cmd_line;
				break;

			case 'l':
				initialize_ldb_tables(ldb_db_name);
				print_osadl_license_data(optarg);
				exit(EXIT_SUCCESS);
				break;

			case 'n':
				ldb_db_name = strdup(optarg);
				break;
			case 'M':
				scan_max_snippets = atol(optarg);
				break;
			case 'N':
				scan_max_components = atol(optarg);
				break;
			case 'w':
				force_wfp = true;
				break;
			case 'B':
				ignore_components = get_components(optarg);
				force_snippet_scan = true;
				break;
			case 't':
				initialize_ldb_tables(ldb_db_name);
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
				engine_flags = engine_flags_cmd_line;
				debug_on = true;
				quiet = true;
				scanlog("Quiet mode enabled. Displaying only debugging info via STDERR.\n");
				break;

			case 'd':
				engine_flags = engine_flags_cmd_line;
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
			
			case 'H':
				if (hpsm_lib_load())
					hpsm_enabled = true;
				else
				{
					printf("'libhpsm.so' must be present in the system to execute this command\n");
					exit(EXIT_FAILURE);
				}
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

		initialize_ldb_tables(ldb_db_name);
		free(ldb_db_name);

		/* Remove trailing backslashes from target (if any) */
		strcpy (target, argv[argc-1]);
		for (int i=strlen(target)-1; i>=0; i--) if (target[i]=='/') target[i]=0; else break;


		/* Open main report structure */
		json_open();

		/* Scan directory */
		if (isdir) recurse_directory(target);

		/* Scan file */
		else
		{
			/* Init scan structure */			
			if (ishash) 
				hash_scan(target, scan_max_snippets, scan_max_components);
			else
			{
				bool wfp_extension = false;
				bool bfp_extension = false;
				if (extension(target)) if (!strcmp(extension(target), "wfp")) wfp_extension = true;
					if (force_wfp) wfp_extension = true;
				
				if (extension(target)) if (!strcmp(extension(target), "bfp")) bfp_extension = true;
					if (force_bfp) bfp_extension = true;

				/* Scan wfp file */
				if (wfp_extension) 
					wfp_scan(target, scan_max_snippets, scan_max_components);

				else if (bfp_extension) 
					binary_scan(target);

				/* Scan file directly */
				else 
				{
					scanlog("Scanning file %s\n", target);
					scan_data_t * scan = scan_data_init(target, scan_max_snippets, scan_max_components);
					ldb_scan(scan);
				}
			}


		}

		/* Close main report structure */
		json_close();

		if (target) free (target);
	}

	if (ignore_components) 
	{
		for (int i = 0; i < MAX_SBOM_ITEMS; i++)
			component_item_free(&ignore_components[i]);
		free(ignore_components);
	}

	if (declared_components) 
	{
		for (int i = 0; i < MAX_SBOM_ITEMS; i++)
			component_item_free(&declared_components[i]);
		free(declared_components);
	}

	if (ignored_assets)  free (ignored_assets);
    
	if (lib_encoder_present)
	{
		dlclose(lib_encoder_handle);
	}
	
	hpsm_lib_close();
	free(component_hint);

	return EXIT_SUCCESS;
}
