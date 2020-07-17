// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/ldb.h
 *
 * LDB Database - A mapped linked-list database
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

#define LDB_MAX_NAME 64
#ifndef _LDB_GLOBAL_
#define _LDB_GLOBAL_

extern const char LDB_VERSION[];
extern char ldb_root[];
extern char ldb_lock_path[];
extern const uint8_t  ldb_key_ln;
extern const uint8_t  ldb_ptr_ln;
extern const uint64_t ldb_sector_map_size;
extern const uint32_t ldb_max_recln;
extern const uint32_t ldb_max_dataln;
extern const uint32_t ldb_max_nodeln;
extern const uint32_t ldb_max_path;
extern const uint32_t ldb_max_command_size;
extern char *ldb_commands[];
extern int ldb_commands_count;
extern int ldb_max_list_record_length;

typedef enum { 
HELP, 
CREATE_DATABASE, 
CREATE_TABLE,
SHOW_DATABASES,
SHOW_TABLES,
INSERT_ASCII, 
INSERT_HEX, 
SELECT_ASCII,
SELECT, 
DELETE,
DROP_DATABASE,
DROP_TABLE,
VERSION,
UNLINK_LIST
} commandtype;

struct ldb_stats
{
    uint32_t counter;
	uint32_t skipped;
};

struct ldb_table
{
	char db[LDB_MAX_NAME];
	char table[LDB_MAX_NAME];
	int  key_ln;
	int  rec_ln; // data record length, otherwise 0 for variable-length data
    int  ts_ln;  // 2 or 4 (16-bit or 32-bit reserved for total sector size)
	bool tmp; // is this a .tmp sector instead of a .ldb?
};

struct ldb_recordset
{
	char db[LDB_MAX_NAME];
	char table[LDB_MAX_NAME];
	FILE *sector;       // Data sector file pointer
	uint8_t key[255];   // Data key
	uint8_t key_ln;     // Key length: 4-255
	uint8_t subkey_ln;  // remaining part of the key that goes into the data: key_ln - 4
	uint8_t rec_ln;     // Fixed length of data records: 0-255, where 0 means variable-length data
	uint8_t *node;      // Pointer to current node. This will point to mallocated memory.
	uint32_t node_ln;   // Length of the current node
	uint8_t *record;    // Pointer to current record within node
	uint64_t next_node; // Location of next node inside the 
	uint64_t last_node; // Location of last node of the list
    uint8_t ts_ln;      // 2 or 4 (16-bit or 32-bit reserved for total sector size)
};

#endif

bool ldb_file_exists(char *path);
bool ldb_dir_exists(char *path);
bool ldb_locked();
void ldb_error (char *txt);
void ldb_prepare_dir(char *path);
void ldb_lock();
void ldb_unlock();
void ldb_create_sector(char *sector_path);
void ldb_uint40_write(FILE *ldb_sector, uint64_t value);
void ldb_uint32_write(FILE *ldb_sector, uint32_t value);
uint32_t ldb_uint32_read(FILE *ldb_sector);
uint64_t ldb_uint40_read(FILE *ldb_sector);
uint16_t ldb_uint16_read(FILE *ldb_sector);
uint16_t uint16_read(uint8_t *pointer);
void uint16_write(uint8_t *pointer, uint16_t value);
uint32_t uint32_read(uint8_t *pointer);
void uint32_write(uint8_t *pointer, uint32_t value);
uint64_t uint40_read(uint8_t *pointer);
void uint40_write(uint8_t *pointer, uint64_t value);
uint64_t ldb_map_pointer_pos(uint8_t *key);
uint64_t ldb_list_pointer(FILE *ldb_sector, uint8_t *key);
uint64_t ldb_last_node_pointer(FILE *ldb_sector, uint64_t list_pointer);
void ldb_update_list_pointers(FILE *ldb_sector, uint8_t *key, uint64_t list, uint64_t new_node);
void ldb_node_write (struct ldb_table table, FILE *ldb_sector, uint8_t *key, uint8_t *data, uint32_t dataln, uint16_t records);
uint64_t ldb_node_read (struct ldb_table table, FILE *ldb_sector, uint64_t ptr, uint8_t *key, uint32_t *bytes_read, uint8_t *out, int max_node_size);
char *ldb_sector_path (struct ldb_table table, uint8_t *key, char *mode, bool tmp);
FILE *ldb_open (struct ldb_table table, uint8_t *key, char *mode);
void ldb_node_unlink (struct ldb_table table, uint8_t *key);
void ldb_hexprint(uint8_t *data, uint32_t len, uint8_t width);
uint8_t ldb_h2d(uint32_t h);
void ldb_hex_to_bin(char *hex, uint8_t *out);
bool ldb_check_root();
bool ldb_valid_hex(char *str);
bool ldb_valid_ascii(char *str);
void ldb_trim(char *str);
struct ldb_table ldb_read_cfg(char *db_table);
void ldb_write_cfg(char *db, char *table, int keylen, int reclen);
int ldb_split_string(char *string, char separator);
bool ldb_valid_name(char *str);
char *ldb_extract_word(int n, char *wordlist);
int ldb_word_count(char *text);
bool ldb_valid_table(char *table);
int ldb_word_len(char *text);
commandtype ldb_syntax_check(char *command, int *command_nr, int *word_nr);
void ldb_command_create_database(char *command);
void ldb_command_normalize(char *text);
void ldb_command_show_tables(char *command);
void ldb_command_show_databases();
void ldb_command_select(char *command, bool ascii);
void ldb_command_telect(char *command);
void ldb_command_insert(char *command, commandtype type);
void ldb_command_create_table(char *command);
void ldb_version();
bool ldb_database_exists(char *db);
bool ldb_table_exists(char *db, char*table);
bool ldb_create_table(char *db, char *table, int keylen, int reclen);
bool ldb_create_database(char *database);
struct ldb_recordset ldb_recordset_init(char *db, char *table, uint8_t *key);
void ldb_list_unlink(FILE *ldb_sector, uint8_t *key);
void ldb_command_unlink_list(char *command);
uint8_t *ldb_load_sector (struct ldb_table table, uint8_t *key);
bool ldb_validate_node(uint8_t *node, uint32_t node_size, int subkey_ln);
uint64_t ldb_node_extract (struct ldb_table table, uint8_t *ldb_sector, uint64_t ptr, uint32_t key, uint32_t *node_size, uint8_t **node, int max_node_size);
bool uint32_is_zero(uint8_t *n);
bool ldb_key_exists(struct ldb_table table, uint8_t *key);
bool ldb_key_in_recordset(uint8_t *rs, uint32_t rs_len, uint8_t *subkey, uint8_t subkey_ln);
uint32_t ldb_fetch_recordset(struct ldb_table table, uint8_t* key, bool (*ldb_record_handler) (uint8_t *, uint32_t, int, void *), void *void_ptr);
bool ldb_asciiprint(uint8_t *data, uint32_t size, int iteration, void *ptr);
bool ldb_hexprint16(uint8_t *data, uint32_t size, int iteration, void *ptr);
