#include "scanoss.h"
#include <stdio.h>
#include "decrypt.h"
struct out_buffer_s {
	char * buffer;
	int pos;
};

struct get_path_s {
	char * path;
	uint8_t * url_key;
};

bool get_path(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	char * path = decrypt_data(data, datalen, *table, key, subkey);
	if (!path) {
		return false;
	}
	char ** out = (char**) ptr;
	*out = path;
	return true;
}

bool get_file_path_hash(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	if (datalen < table->key_ln)
		return false;
	struct get_path_s * get_path_url = ptr;
	//if the url key is not the same is not a useful match
	if (memcmp(get_path_url->url_key, data, table->key_ln))
		return false;

	uint8_t * path_key = &data[table->key_ln];
	char * path = NULL;
	fetch_recordset(oss_path, path_key, get_path, (void *)&path);
	get_path_url->path = path;
	return true;
}


bool get_project_hashes(struct ldb_table * table, uint8_t *key, uint8_t *subkey, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	uint8_t * file_key = data;
	struct get_path_s get_path = {.url_key = key, .path = NULL};
	char key_hex[17];
	ldb_bin_to_hex(file_key,table->key_ln,key_hex);

	fetch_recordset(oss_file, file_key, get_file_path_hash, (void *)&get_path);
	char * output = ptr;
	char * line = NULL;
	if (get_path.path)
	{
		asprintf(&line, "%s,%s\n", key_hex, get_path.path);
		strcat(output, line);
		free(line);
	}

	free(get_path.path);
	return false;
}

void get_project_files(char * url_key_hex)
{
	uint8_t url_key[8];
	ldb_hex_to_bin(url_key_hex, 16, url_key);
	char * out = calloc(1,1024*1024*500);
	fetch_recordset(oss_pivot, url_key, get_project_hashes, (void *)out);
	printf("%s", out);
}