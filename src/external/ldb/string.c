// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/string.c
 *
 * String handling routines
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

bool ldb_valid_ascii(char *str)
{
	if (strlen(str) < 1) return false;
	for (int i = 0; i < strlen(str); i++) 
		if (str[i] < 33 || str[i] > 126) return false;
	return true;
}

void ldb_trim(char *str)
{
	int i = 0;

	/* Left trim */
	int len = strlen(str);
	for (i = 0; i < len; i++) if (!isspace(str[i])) break;
	if (i) memmove(str, str + i, strlen(str + i) + 1);

	/* Right trim */
	len = strlen(str);
	for (i = len - 1; i >= 0 ; i--) if (!isspace(str[i])) break;
	str[i + 1] = 0;
}

int ldb_split_string(char *string, char separator)
{
	int pos;
	for (pos = 0; pos < strlen(string); pos++) if (string[pos] == separator) break;
	string[pos] = 0;
	return pos + 1;
}

bool ldb_valid_name(char *str)
{
	if (strlen(str) >= LDB_MAX_NAME) return false;
	if (strstr(str, "/")) return false;
	if (strstr(str, ".")) return false;
	return true;
}

bool ldb_asciiprint(uint8_t *data, uint32_t size, int iteration, void *ptr)
{
	for (int i = 0; i < size; i++)
		if (data[i] >= 32 && data[i] <= 126)
			fwrite(data + i, 1, 1, stdout);
		else
			fwrite(".", 1, 1, stdout);

	fwrite("\n", 1, 1, stdout);
	return false;
}

int ldb_word_len(char *text)
{
	for (int i=0; i<strlen(text); i++) if (text[i] == ' ') return i;
	return strlen(text);
}

bool ldb_valid_table(char *table)
{

	// Make sure there is at least a byte before and after a slash
	int s = 0;
	int c = 0;
	for (int i = 0; i < strlen(table); i++)
	{
		if (table[i] == '/') 
		{
			c++;
			s = i;
		}
	}
	if (s < 1 || s > (strlen(table) - 1) || c != 1) 
	{
		printf("E060 Table name format should be dbname/tablename\n");
		return false;
	}

	// Verify that db/table path is not too long
	if (strlen(table) + strlen(ldb_root) + 1 >= ldb_max_path)
	{
		printf("E061 db/table name is too long\n");
		return false;
	}

	bool out = true;

	char *db_path    = malloc(ldb_max_path);
	sprintf(db_path, "%s/%s", ldb_root, table);
	db_path[strlen(ldb_root) + 1 + s] = 0;

	char *table_path    = malloc(ldb_max_path);
	sprintf(table_path, "%s/%s", ldb_root, table);

	// Verify that db exists

	if (!ldb_dir_exists(db_path)) 
	{
		printf("E062 Database %s does not exist\n", db_path + strlen(ldb_root) + 1);
		out = false;
	}

	// Verify that table exists
	else if (!ldb_dir_exists(table_path))
	{
		printf("E063 Table %s does not exist\n", table);
		out = false;
	}

	free(db_path);
	free(table_path);

	return out;
}


/* Counts number of words in normalized text */
int ldb_word_count(char *text)
{
	int words = 1;
	for (int i = 0; i < strlen(text); i++) if (text[i] == ' ') words++;
	return words;
}

/* Returns a pointer to a string containing the n word of the (normalized) list */
char *ldb_extract_word(int n, char *wordlist)
{
	int word_start = 0;
	char *out = calloc(ldb_max_command_size, 1);

	// Look for word start
	if (n>1)
	{
		int c = 2;
		for (int i = 1; i < strlen(wordlist); i++)
		{
			if (wordlist[i] == ' ') 
			{
				if (c++ == n) 
				{
					word_start = i + 1;
					break;
				}
			}
		}
		if (word_start == 0) return out;
	}

	// Copy desired word to out
	memcpy(out, wordlist + word_start, ldb_word_len(wordlist + word_start));
	return out;

}
