#include "match_list.h" 
#include "debug.h"
#include "snippets.h"
#include "scanoss.h"
#include "file.h"
#include "util.h"
#include "match.h"
/**
 * @brief Handler function to collect all file ids.
 * Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr //TODO
 * @return //TODO
 */
static bool get_all_file_ids(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	uint8_t *record = (uint8_t *) ptr;
	if (datalen)
	{
		uint32_t size = uint32_read(record);

		/* End recordset fetch if MAX_QUERY_RESPONSE is reached */
		if (size + datalen + 4 >= MAX_QUERY_RESPONSE) return true;

		/* End recordset fetch if MAX_FILES are reached for the snippet */
		if ((WFP_REC_LN * matchmap_max_files) <= (size + datalen)) return true;

		/* Save data and update dataln */
		memcpy(record + size + 4, data, datalen);
		uint32_write(record, size + datalen);
	}
	return false;
}


static void add_files_to_matchmap(scan_data_t *scan, uint8_t *md5s, uint32_t md5s_ln, uint8_t *wfp)
{
	long map_rec_len = sizeof(matchmap_entry);
	scanlog("<<< %d - md5eln >>>\n", md5s_ln);
	/* Recurse each record from the wfp table */
	for (int n = 0; n < md5s_ln; n += WFP_REC_LN)
	{
		/* Retrieve an MD5 from the recordset */
		memcpy(scan->md5, md5s + n, MD5_LEN);

		/* Check if md5 already exists in map */
		long found = -1;
		for (long t = 0; t < scan->matchmap_size; t++)
		{
			if (md5cmp(scan->matchmap[t].md5, scan->md5))
			{
				found = t;
				break;
			}
		}

		if (found < 0)
		{
			/* Not found. Add MD5 to map */
			if (scan->matchmap_size >= matchmap_max_files) 
			{
				scanlog("<<< %d/%d - MAX MACHMAP >>>\n", n, md5s_ln);
				continue;
			}

			found = scan->matchmap_size;

			/* Clear row */
			memset(scan->matchmap[found].md5, 0, map_rec_len);

			/* Write MD5 */
			memcpy(scan->matchmap[found].md5, scan->md5, MD5_LEN);
		}

		/* Search for the right range */
		uint8_t *lastwfp = scan->matchmap[found].lastwfp;

		/* Skip if we are hitting the same wfp again for this file) */
		if (!memcmp(wfp, lastwfp, 4)) continue;
		
		scan->matchmap[found].hits++;
		if (scan->matchmap[found].hits > 1)
			scanlog("<<hits++ %d>>\n",scan->matchmap[found].hits);
	
		/* Update last wfp */
		memcpy(lastwfp, wfp, 4);

		if (found == scan->matchmap_size) scan->matchmap_size++;
	}
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
int binary_scan(char * path, int scan_max_snippets, int scan_max_components)
{
	struct ldb_table oss_fhash = {.db = "test", .table = "fhashes", .key_ln = 16, .rec_ln = 0, .ts_ln = 2, .tmp = false};
	scan_data_t * scan = NULL;
	char * line = NULL;
	size_t len = 0;
	ssize_t lineln;
    int hash_count = 0;
	/* Open WFP file */
	FILE *fp = fopen(path, "r");
	if (fp == NULL)
	{
		fprintf(stdout, "E017 Cannot open target");
		return EXIT_FAILURE;
	}
	scanlog("<<< Binary scan>>>>\n");
	/* Get wfp MD5 hash */
	uint8_t tmp_md5[16];
	get_file_md5(path, tmp_md5);
	char *tmp_md5_hex = md5_hex(tmp_md5);
	uint8_t *md5_set = calloc(1, MAX_QUERY_RESPONSE);

	/*Init a new scan object for the next file to be scanned */
	scan = scan_data_init(path, 1, scan_max_components);

	/* Read line by line */
	while ((lineln = getline(&line, &len, fp)) != -1)
	{
		trim(line);

		bool is_file = (memcmp(line, "file=", 5) == 0);

		/* Parse file information with format: file=MD5(32),file_size,file_path */
		if (is_file)
		{
			// /* A scan data was fullfilled and is ready to be scanned */
			// if (scan)
			// 	ldb_scan(scan);
			
			// /* Prepare the next scan */
			// const int tagln = 5; // len of 'file='

			// /* Get file MD5 */
			// char * hexmd5 = strndup(line + tagln, MD5_LEN * 2);

			// /* Extract fields from file record */
			// calloc(LDB_MAX_REC_LN, 1);  
			
			// rec = (uint8_t*) strdup(line + tagln + (MD5_LEN * 2) + 1);
			// char * target = field_n(2, (char *)rec);
			
			// /*Init a new scan object for the next file to be scanned */
			// scan = scan_data_init(target, scan_max_snippets, scan_max_components);
			// strcpy(scan->source_md5, tmp_md5_hex);
			// extract_csv(scan->file_size, (char *)rec, 1, LDB_MAX_REC_LN);
			// scan->preload = true;
			// free(rec);
			// ldb_hex_to_bin(hexmd5, MD5_LEN * 2, scan->md5);
			// free(hexmd5);
		} 

		else 
		{
			//scanlog("Processing FHASH: %s\n", line);
			/* Convert hash to binary */
			uint8_t fhash[16]; 
			ldb_hex_to_bin(line, 32, fhash);
			hash_count++;
			/* Get all file IDs for given wfp */
			uint32_write(md5_set, 0);
			ldb_fetch_recordset(NULL, oss_fhash, fhash, false, get_all_file_ids, (void *) md5_set);
			/* md5_set starts with a 32-bit item count, followed by all 16-byte records */
			uint32_t md5s_ln = uint32_read(md5_set);
			uint8_t *md5s = md5_set + 4;

			//	scanlog("Snippet %02x%02x%02x%02x (line %d) -> %u hits %s\n", wfp[0], wfp[1], wfp[2], wfp[3], line, md5s_ln / WFP_REC_LN, traced ? "*" : "");
			if (md5s_ln && md5s_ln < 10000)
				add_files_to_matchmap(scan, md5s, md5s_ln, fhash);
		}
	}
	free(md5_set);
	fclose(fp);
	if (line) free(line);
	
	free(tmp_md5_hex);
	if (debug_on)
		map_dump(scan);

		/* Scan the last file */
	scan->match_type = MATCH_BINARY;
	compile_matches(scan);
	scanlog("Match output starts\n");
	output_matches_json(scan);

	//if (matches) free(matches);
	scan_data_free(scan);
	return EXIT_SUCCESS;
}