// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/query.c
 *
 * High level data queries
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

/* Obtain the first file name for the given file MD5 hash */
char *get_filename(char *md5)
{
	/* Convert md5 to bin */
	uint8_t md5bin[MD5_LEN];
	hex_to_bin(md5, MD5_LEN * 2, md5bin);

	/* Init record */
	uint8_t *record = calloc(LDB_MAX_REC_LN + 1, 1);

	/* Fetch first record */
	ldb_get_first_record(oss_file, md5bin, (void *) record);

	uint32_t recln = uint32_read(record);
	if (record)
	{
		memmove(record, record + 4, recln);
		record[recln] = 0;
	}

	return (char *)record;
}

/* Handler function for ldb_get_first_non_blacklisted */
bool ldb_get_first_non_blacklisted(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
    uint8_t *record = (uint8_t *) ptr;

    if (datalen) if (!blacklist_match(data + 4)) 
	{
		/* Not blacklisted, means copy record and exit */
		uint32_write(record, datalen);
		memcpy(record + 4, data, datalen);
		record[datalen + 4 + 1] = 0;
		return true;
	}

    return false;
}


/* Obtain the first available component record for the given MD5 hash */
void get_component_record(uint8_t *md5, uint8_t *record)
{
	/* Erase byte count */
	uint32_write(record, 0);

	/* Fetch record */
    ldb_fetch_recordset(NULL, oss_component, md5, false, ldb_get_first_non_blacklisted, (void *) record);

	/* Erase record length prefix from record */
	uint32_t recln = uint32_read(record);
	if (recln) 
	{
		memmove(record, record+4, recln);
		record[recln] = 0;
	}

}
