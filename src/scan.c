// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/scan.c
 *
 * Scan-related subroutines
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

#include "debug.h"
#include "file.h"
#include "ignorelist.h"
#include "ldb.h"
#include "limits.h"
#include "match.h"
#include "parse.h"
#include "query.h"
#include "rank.h"
#include "scan.h"
#include "snippets.h"
#include "util.h"
#include "versions.h"
#include "winnowing.h"
#include "hpsm.h"
#include "match_list.h"
#include "report.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>



/**
  @file scan.c
  @date 12 Jul 2020
  @brief Scan-related subroutines.
 
  Long description // TODO
  @see https://github.com/scanoss/engine/blob/master/src/scan.c
 */
bool first_file = true;											  /** global first file flag */

char *ignored_assets = NULL;

/** @brief Init scan structure 
    @param target File to scan
    @return Scan data
    */
scan_data_t * scan_data_init(char *target, int max_snippets, int max_components)
{
	scanlog("Scan Init\n");
	scan_data_t * scan = calloc(1, sizeof(*scan));
	scan->file_path = strdup(target);
	scan->file_size = malloc(32);
	scan->hashes = malloc(MAX_FILE_SIZE);
	scan->lines  = malloc(MAX_FILE_SIZE);
	scan->match_type = MATCH_NONE;

	scan->max_components_to_process = max_components;
	
	scan->max_snippets_to_process = max_snippets > MAX_MULTIPLE_COMPONENTS ? MAX_MULTIPLE_COMPONENTS : max_snippets; 
	scan->max_snippets_to_process = scan->max_snippets_to_process == 0 ? 1 : scan->max_snippets_to_process;
	matchmap_max_files = scan->max_snippets_to_process * MAX_FILES;
	scan->matchmap = calloc(matchmap_max_files, sizeof(matchmap_entry));
	return scan;
}

/** @brief Frees scan data memory
    @param scan Scan data
	*/
void scan_data_free(scan_data_t * scan)
{
	for (int i=0; i < scan->matches_list_array_index; i++)
		match_list_destroy(scan->matches_list_array[i]);
	
	free(scan->file_path);
	free(scan->file_size);
	free(scan->hashes);
	free(scan->lines);
	free(scan->matchmap);
	free(scan);
	scan = NULL;
}

/** @brief Returns true if md5 is the md5sum for NULL
    @param md5 File ID (md5)
    @result Empty file result
	  */
static bool zero_bytes (uint8_t *md5)
{
	uint8_t empty[] = "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e";

	for (int i = 0; i < 15; i++)
		if (md5[i] != empty[i]) return false;

	return true;
}

/**
 * @brief Scans against file and url tables, looking for a full file match.
 * If the match is against url table set "url_match" as true.
 * @param scan scan object being scanned.
 * @return match_t 
 */
static match_t ldb_scan_file(scan_data_t * scan) {
			
	scanlog("Checking entire file\n");
	
	if (zero_bytes(scan->md5)) return MATCH_NONE;
	
	match_t match_type = MATCH_NONE;

	if (ldb_key_exists(oss_url, scan->md5) || ldb_key_exists(oss_file, scan->md5)) 
	{
		match_type = MATCH_FILE;
	}

	return match_type;
}

/** @brief Return true if asset is found in declared_components (-s parameter)
    @param match Match data
    @return Asset declaration result
    */
int asset_declared(component_data_t * comp)
{
	if (!declared_components)
		return 0;

	if (comp->identified > 0)
		return comp->identified;
	
	/* Travel declared_components */
	for (int i = 0; i < MAX_SBOM_ITEMS; i++)
	{
		char *vendor = declared_components[i].vendor;
		char *component = declared_components[i].component;
		char *purl = declared_components[i].purl;
		char *version = declared_components[i].version;

		/* Exit if reached the end */
		if (!component && !vendor && !purl) 
			break;

		/* Compare purl */
		if (comp->purls[0])
		{
			if (!strcmp((const char *) purl, (const char *) comp->purls[0])) 
			{
				if (version && !strcmp(version, comp->version))
				{
					scanlog("version found: %s\n",version);
					comp->identified = IDENTIFIED_PURL_VERSION;
					return IDENTIFIED_PURL_VERSION;
				}
				comp->identified = IDENTIFIED_PURL;
				scanlog("purl found: %s\n",purl);
				return IDENTIFIED_PURL;
			}
		}

		/* Compare vendor and component */
		if (comp->vendor && comp->component && vendor && component)
		{
			if (!strcmp(vendor, comp->vendor) && !strcmp(component, comp->component)) 
			{
				scanlog("Vendor %s + comp %s found\n",vendor, component);
				comp->identified = 1;
				return IDENTIFIED_PURL;
			}
		}
	}
	return IDENTIFIED_NONE;
}


/** @brief Scans a file hash only
 *   @param scan Scan data
 *   @return Scan result (SUCCESS/FAILURE)
|**/
int hash_scan(char *path, int scan_max_snippets, int scan_max_components)
{
	scan_data_t * scan = scan_data_init(path, scan_max_snippets, scan_max_components);
	scan->preload = true;

		/* Get file MD5 */
	ldb_hex_to_bin(scan->file_path, MD5_LEN * 2, scan->md5);

	/* Fake file length */
	strcpy(scan->file_size, "999");

	/* Scan the last file */
	char * report = ldb_scan(scan);
	printf("%s", report);
	free(report);

	return EXIT_SUCCESS;
}


#define SERVER_QUEUE_NAME   "/scanoss-api"
#define CLIENT_QUEUE_NAME   "/scanoss-engine"
#define QUEUE_PERMISSIONS 0660
#define MAX_MESSAGES 5
#define MAX_MSG_SIZE 1024 * 64
#define MSG_BUFFER_SIZE MAX_MSG_SIZE + 10

int wfp_mq_scan(int scan_max_snippets, int scan_max_components)
{
    mqd_t qd_server, qd_client;   // queue descriptors

    struct mq_attr attr;
	
	scan_data_t * scan = NULL;
	uint8_t * rec = NULL;

    attr.mq_flags = 0;
    attr.mq_maxmsg = MAX_MESSAGES;
    attr.mq_msgsize = MAX_MSG_SIZE;
    attr.mq_curmsgs = 0;

    if ((qd_client = mq_open (CLIENT_QUEUE_NAME, O_RDONLY | O_CREAT, QUEUE_PERMISSIONS, &attr)) == -1) {
        perror ("Client: mq_open (client)");
		 if (mq_unlink (CLIENT_QUEUE_NAME) == -1) {
        perror ("Client: mq_unlink");
        exit (1);
    }
        exit (1);
    }

    if ((qd_server = mq_open (SERVER_QUEUE_NAME, O_WRONLY)) == -1) {
        perror ("Client: mq_open (server)");
        exit (1);
    }

    char in_buffer [MSG_BUFFER_SIZE];

    printf ("Ask for a token (Press <ENTER>): ");

	while(1)
	{
		ssize_t result = mq_receive (qd_client, in_buffer, MSG_BUFFER_SIZE, NULL);
		if (result == -1) 
		{
            perror ("Client: mq_receive");
            exit (1);
        }
		else if (result >= 0)
		{
			printf("Rec: %s", in_buffer);
			  /* get the first token */
			char * line = in_buffer;
			
			/* walk through other tokens */
			while(line != NULL) 
			{
				trim(line);
				bool is_file = (memcmp(line, "file=", 5) == 0);
				bool is_hpsm = (memcmp(line, "hpsm=", 5) == 0);
				bool is_wfp = (!is_file && !is_hpsm);

				if (is_hpsm) 
				{
					hpsm_enabled = hpsm_lib_load();
					hpsm_crc_lines = strdup(&line[5]);
				}

				if (is_file)
				{
						/* Prepare the next scan */
					const int tagln = 5; // len of 'file='

					/* Get file MD5 */
					char * hexmd5 = strndup(line + tagln, MD5_LEN * 2);

					/* Extract fields from file record */
					calloc(LDB_MAX_REC_LN, 1);  
					
					rec = (uint8_t*) strdup(line + tagln + (MD5_LEN * 2) + 1);
					char * target = field_n(2, (char *)rec);
					
					/*Init a new scan object for the next file to be scanned */
					scan = scan_data_init(target, scan_max_snippets, scan_max_components);
					extract_csv(scan->file_size, (char *)rec, 1, LDB_MAX_REC_LN);
					scan->preload = true;
					free(rec);
					scanlog("File md5 to be scanned: %s\n", hexmd5);
					ldb_hex_to_bin(hexmd5, MD5_LEN * 2, scan->md5);
					free(hexmd5);
				}

				if (is_wfp && scan && (scan->hash_count < MAX_HASHES_READ))
				{
					/* Split string by the equal and commas */
					int line_ln = strlen(line);
					for (int e = 0; e < line_ln; e++) if (line[e]=='=' || line[e]==',') line[e] = 0;

					/* Extract line number */
					int line_nr = atoi(line);

					/* Move pointer to the first hash */
					char *hexhash = line + strlen(line) + 1;

					/* Save all hashes in the present line */
					while (*hexhash) 
					{

						/* Convert hash to binary */
						ldb_hex_to_bin(hexhash, 8, (uint8_t *)&scan->hashes[scan->hash_count]);
						uint32_reverse((uint8_t *)&scan->hashes[scan->hash_count]);

						/* Save line number */
						scan->lines[scan->hash_count] = line_nr;

						/* Move pointer to the next hash */
						hexhash += strlen(hexhash) + 1;

						scan->hash_count++;
					}
				}
						
				line = strchr(line, '\n');
				if (line)
					line++;
			}
			char * report = ldb_scan(scan);
			printf("%s", report);
			free(report);
		}
	}


    if (mq_close (qd_client) == -1) {
        perror ("Client: mq_close");
        exit (1);
    }

    if (mq_unlink (CLIENT_QUEUE_NAME) == -1) {
        perror ("Client: mq_unlink");
        exit (1);
    }
    printf ("Client: bye\n");

    exit (0);
}





/**
 * @brief Performs a wfp scan.
 * Files with wfp extension will be scanned in this mode. 
 * Remember: wfp = Winnowings Finger Print.
 * This file could be generated with a client.
 * @param path wfp file path
 * @param scan_max_snippets Limit for matches list. Autolimited be default.
 * @param scan_max_components Limit for component to be displayed. 1 by default.
 * @return EXIT_SUCCESS
 */
#define FRAGMENT_SYMBOL '#'
int wfp_scan(char * path, bool mode_stream, int scan_max_snippets, int scan_max_components)
{
	scan_data_t * scan = NULL;
	char * line = NULL;
	size_t len = 0;
	ssize_t lineln;
	uint8_t *rec = NULL;
	FILE *fp = stdin;
	char *tmp_md5_hex = NULL;
	scanlog("--- WFP SCAN ---\n");
	/* Open WFP file */
	if (path)
	{
		fp = fopen(path, "r");
		if (fp == NULL)
		{
			fprintf(stdout, "E017 Cannot open target");
			return EXIT_FAILURE;
		}
		/* Get wfp MD5 hash */
		uint8_t tmp_md5[16];
		get_file_md5(path, tmp_md5);
		tmp_md5_hex = md5_hex(tmp_md5);
	}
	
	bool is_end = true;

	/* Read line by line */
	while ((lineln = getline(&line, &len, fp)) != -1 || mode_stream || mode_stream)
	{
		if (lineln < 0)
			continue;

		if (lineln < 0)
			continue;

		trim(line);

		bool is_file = (memcmp(line, "file=", 5) == 0);
		bool is_hpsm = (memcmp(line, "hpsm=", 5) == 0);
		
		if (is_end && mode_stream)
			printf("{");
		
		is_end = (memcmp(line, "#", 1) == 0);

		
		if (is_end && mode_stream)
			printf("{");
		
		is_end = (memcmp(line, "#", 1) == 0);

		bool is_wfp = (!is_file && !is_hpsm && !is_end && !is_end);

		if (is_hpsm) 
		{
			hpsm_enabled = hpsm_lib_load();
			hpsm_crc_lines = strdup(&line[5]);
		}

		/* Parse file information with format: file=MD5(32),file_size,file_path */
		if (is_file)
		{
			/* A scan data was fullfilled and is ready to be scanned */
			if (scan)
			{
				char * report = ldb_scan(scan);
				printf("%s", report);
				free(report);
			}
			
			/* Prepare the next scan */
			const int tagln = 5; // len of 'file='

			/* Get file MD5 */
			char * hexmd5 = strndup(line + tagln, MD5_LEN * 2);

			/* Extract fields from file record */
			calloc(LDB_MAX_REC_LN, 1);  
			
			rec = (uint8_t*) strdup(line + tagln + (MD5_LEN * 2) + 1);
			char * target = field_n(2, (char *)rec);
			
			/*Init a new scan object for the next file to be scanned */
			scan = scan_data_init(target, scan_max_snippets, scan_max_components);
			if(tmp_md5_hex)
				if(tmp_md5_hex)
				strcpy(scan->source_md5, tmp_md5_hex);
			extract_csv(scan->file_size, (char *)rec, 1, LDB_MAX_REC_LN);
			scan->preload = true;
			free(rec);
			scanlog("File md5 to be scanned: %s\n", hexmd5);
			ldb_hex_to_bin(hexmd5, MD5_LEN * 2, scan->md5);
			free(hexmd5);
		}
		else if (is_end && mode_stream)
		{
			if (scan)
				ldb_scan(scan);
			scan = NULL;
			printf("}");
			continue;
		}
		else if (is_end && mode_stream)
		{
			if (scan)
				ldb_scan(scan);
			scan = NULL;
			printf("}");
			continue;
		}

		/* Save hash/es to memory. Parse file information with format:
			 linenr=wfp(6)[,wfp(6)]+ */

		if (is_wfp && scan && (scan->hash_count < MAX_HASHES_READ))
		{
			/* Split string by the equal and commas */
			int line_ln = strlen(line);
			for (int e = 0; e < line_ln; e++) if (line[e]=='=' || line[e]==',') line[e] = 0;

			/* Extract line number */
			int line_nr = atoi(line);

			/* Move pointer to the first hash */
			char *hexhash = line + strlen(line) + 1;

			/* Save all hashes in the present line */
			while (*hexhash) {

				/* Convert hash to binary */
				ldb_hex_to_bin(hexhash, 8, (uint8_t *)&scan->hashes[scan->hash_count]);
				uint32_reverse((uint8_t *)&scan->hashes[scan->hash_count]);

				/* Save line number */
				scan->lines[scan->hash_count] = line_nr;

				/* Move pointer to the next hash */
				hexhash += strlen(hexhash) + 1;

				scan->hash_count++;
			}
		}
	}
	/* Scan the last file */
	char * report = ldb_scan(scan);
	printf("%s", report);
	free(report);

	if (path)
		fclose(fp);
		
	if (line) free(line);
	
	free(tmp_md5_hex);
	return EXIT_SUCCESS;
}

/**
 * @brief Output matches in JSON format via STDOUT
 * @param matches pointer to matches list
 * @param scan_ptr scan_data_t pointer, common scan information.
 */
char * report1 = NULL;
void output_matches_json(scan_data_t *scan, char * report)
{
	flip_slashes(scan->file_path);
	report1 = report;
	/* Log slow query, if needed */
	slow_query_log(scan);

	/* Print comma separator */
	if (!first_file)
		strcat(report, ",");
	
	first_file = false;

	uint64_t engine_flags_aux = engine_flags;
	int len = 0;
	/* Print matches */
	if (engine_flags & DISABLE_BEST_MATCH)
	{
		len += sprintf(report+len,"\"%s\": [", scan->file_path);
		bool first = true;
		for (int i = 0; i < scan->matches_list_array_index; i++)
		{
			if (!first && scan->matches_list_array[i]->items && scan->matches_list_array[i]->best_match->component_list.items)
				len += sprintf(report+len,",");
			match_list_print(scan->matches_list_array[i], print_json_match, report, ",");
			first = false;
		}
	}
	/* prinf no match if the scan was evaluated as none */ // TODO must be unified with the "else" clause
	else if (scan->match_type == MATCH_NONE)
	{
		len += sprintf(report+len,"\"%s\": [{", scan->file_path);
		print_json_nomatch(scan, report);
	}
	else if (scan->matches_list_array_index > 1 && scan->max_snippets_to_process > 1)
	{
		engine_flags |= DISABLE_BEST_MATCH;
		len += sprintf(report+len,"\"%s\": {\"matches\":[", scan->file_path);
		match_list_t *best_list = match_select_m_component_best(scan);
		scanlog("<<<best list items: %d>>>\n", best_list->items);
		match_list_print(best_list, print_json_match, report, ",");
		match_list_destroy(best_list);
	}
	else if (scan->best_match && scan->best_match->component_list.items)
	{
		len += sprintf(report+len,"\"%s\": [{", scan->file_path);
		print_json_match(scan->best_match, report);
	}
	else
	{
		len += sprintf(report+len,"\"%s\": [{", scan->file_path);
		print_json_nomatch(scan, report);
	}

	json_close_file(scan, report);
	engine_flags = engine_flags_aux;
}


/**
 * @brief Scans a file and returns JSON matches via STDOUT.
 * scan structure can be already preloaded (.wfp scan)
 * otherwise, it will be loaded here (scanning a physical file) 
 * 
 * @param scan 
 */
char * ldb_scan(scan_data_t * scan)
{
	bool skip = false;
	if (!scan)
		return NULL;

	if (unwanted_path(scan->file_path))
	{
		skip = true;
		scanlog("File %s skipped by path", scan->file_path);
	} 

	scan->matchmap_size = 0;
	scan->match_type = MATCH_NONE;
	scan->timer = microseconds_now();

	/* Get file length */
	uint64_t file_size = 0;
	if (!skip)
	{
		if (scan->preload) file_size = atoi(scan->file_size);
		else file_size = get_file_size(scan->file_path);
		if (file_size < 0) ldb_error("Cannot access file");
	}

	/* Calculate MD5 hash (if not already preloaded) */
	if (!skip) if (!scan->preload) get_file_md5(scan->file_path, scan->md5);

	if (!skip && extension(scan->file_path) && ignored_extension(scan->file_path)) 
	{
		skip = true;
		scanlog("File %s skipped by extension", scan->file_path);
	}

	/* Ignore <=1 byte */
	if (file_size <= MIN_FILE_SIZE) 
	{
		skip = true;
		scanlog("File %s skipped by file size", scan->file_path);
	}

	if (!skip)
	{
		/* Scan full file */
		char *tmp_md5_hex = md5_hex(scan->md5);
		strcpy(scan->source_md5, tmp_md5_hex);
		free(tmp_md5_hex);
	
	/* Look for full file match or url match in ldb */
		scan->match_type = ldb_scan_file(scan);
		
		/* If no match, scan snippets */
		if (scan->match_type == MATCH_NONE)
		{
			/* Load snippets into scan data */
			if (!scan->preload)
			{
				/* Read file into memory */
				char *src = calloc(MAX_FILE_SIZE, 1);
				if (file_size < MAX_FILE_SIZE) read_file(src, scan->file_path, 0);
				
				/* If HPSM is enable calculate the crc8 line hash calling the shared lib */
				if(hpsm_enabled) 
				{
					char *aux = hpsm_hash_file_contents(src);
					if(aux)
					{
						hpsm_crc_lines = strdup(&aux[5]);
						free(aux);
					}
				}					
				/* Determine if file is to skip snippet search */
				if (!skip_snippets(src, file_size))
				{	/* Load wfps into scan structure */
					scan->hash_count = winnowing(src, scan->hashes, scan->lines, MAX_FILE_SIZE);
					if (scan->hash_count) scan->total_lines = scan->lines[scan->hash_count - 1];
				}
				free(src);
			}
			else if (scan->hash_count) scan->total_lines = scan->lines[scan->hash_count - 1];

			/* Perform snippet scan */
			if (scan->total_lines) scan->match_type = ldb_scan_snippets(scan);

			else scanlog("File skipped\n");
		}
	}

	/* Compile matches */
	compile_matches(scan);

	if (!scan->best_match)
		scanlog("No best match\n");
	
	/* Output matches */
	scanlog("Match output starts\n");
	char * report = calloc(MAX_FILE_SIZE, 1);
	output_matches_json(scan, report);
	scan_data_free(scan);
	return report;
}
