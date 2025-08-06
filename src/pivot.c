#include "scanoss.h"
#include <stdio.h>
#include "decrypt.h"
#include "debug.h"
#include "file.h"
struct out_buffer_s {
	char * buffer;
	int pos;
};

struct get_path_s {
	char **paths;
	uint8_t * url_key;
	int paths_index;
};


bool get_file_path_hash(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	if (datalen < table->key_ln)
		return false;
	struct get_path_s * get_path_url = ptr;
	//if the url key is not the same is not a useful match
	if (memcmp(get_path_url->url_key, data, table->key_ln))
		return false;

	char * decrypted = NULL;
	
	if (path_table_present)
	{
		decrypted = path_query(&data[table->key_ln]);
	}
	else
	{
		/* Decrypt data */
		decrypted = decrypt_data(data, datalen, *table, key, subkey);
	}
	
	
	get_path_url->paths = realloc(get_path_url->paths, (get_path_url->paths_index + 1) * sizeof(char*));
	get_path_url->paths[get_path_url->paths_index] = decrypted;
	get_path_url->paths_index++;
	return true;
}


bool get_project_hashes(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	uint8_t * file_key = data;
	struct get_path_s get_path = {.url_key = key, .paths = NULL, .paths_index = 0};
	char key_hex[oss_url.key_ln*2+1];
	ldb_bin_to_hex(file_key,table->key_ln,key_hex);

	fetch_recordset(oss_file, file_key, get_file_path_hash, (void *)&get_path);
	char * output = ptr;
	char * line = NULL;
	for (int i = 0; i < get_path.paths_index; i++)
	{
		asprintf(&line, "%s,%s\n", key_hex, get_path.paths[i]);
		free(get_path.paths[i]);
		strcat(output, line);
		free(line);
	}

	free(get_path.paths);
	return false;
}

void get_project_files(char * url_key_hex)
{
	uint8_t url_key[oss_url.key_ln];
	scanlog("Reconstructing project structure for url %s\n",url_key_hex);
	if (!ldb_table_exists(oss_pivot.db, oss_pivot.table))
	{
		printf("the pivot table must be present to use this functionality\n");
		exit(EXIT_FAILURE);
	}
	ldb_hex_to_bin(url_key_hex, oss_url.key_ln*2, url_key);
	char * out = calloc(1,1024*1024*500);
	fetch_recordset(oss_pivot, url_key, get_project_hashes, (void *)out);
	printf("%s", out);
}