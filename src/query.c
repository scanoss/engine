// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/query.c
 *
 * High level data queries
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
  * @file query.c
  * @date 12 Jul 2020 
  * @brief Contains the functions used for component ldb queries
  
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/quality.c
  */

#include "query.h"
#include "util.h"
#include "time.h"
#include "limits.h"
#include "ldb.h"
#include "scanoss.h"
#include "decrypt.h"

/**
 * @brief Obtain the first file name for the given file MD5 hash
 * @param md5 MD5 hash
 * @return string witht he file name
 */
char *get_filename(char *md5)
{
	/* Convert md5 to bin */
	uint8_t md5bin[MD5_LEN];
	ldb_hex_to_bin(md5, MD5_LEN * 2, md5bin);

	/* Init record */
	uint8_t *record = calloc(LDB_MAX_REC_LN + 1, 1);

	/* Fetch first record */
	ldb_get_first_record(oss_file, md5bin, (void *) record);

	uint32_t recln = uint32_read(record);
	if (record)
	{
		memmove(record, record + 4, recln);
		record[recln] = 0;

		/* Decrypt data */
		decrypt_data(record, recln, "file", md5bin, md5bin + LDB_KEY_LN);
	}

	return (char *)record;
}

/**
 * @brief Handler function for get_url_record. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param key //TODO
 * @param subkey //TODO
 * @param subkey_ln //TODO
 * @param data //TODO
 * @param datalen //TODO
 * @param iteration //TODO
 * @param ptr //TODO
 * @return //TODO
 */
bool ldb_get_first_url_not_ignored(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	decrypt_data(data, datalen, "url", key, subkey);

	uint8_t *record = (uint8_t *) ptr;

	if (datalen) if (!ignored_asset_match(data))
	{
		/* Not ignored, means copy record and exit */
		memcpy(record, data, datalen);
		record[datalen] = 0;
		return true;
	}

	return false;
}

/**
 * @brief Obtain the first available component record for the given MD5 hash
 * @param md5 MD5 hash
 * @param record[out] Output pointer to record
 */
void get_url_record(uint8_t *md5, uint8_t *record)
{
	*record = 0;

	/* Fetch record */
	ldb_fetch_recordset(NULL, oss_url, md5, false, ldb_get_first_url_not_ignored, (void *) record);
}

/**
 * @brief Extracts component age in seconds from created date (1st CSV field in data). 
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
bool handle_get_component_age(uint8_t *key, uint8_t *subkey, int subkey_ln, \
uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	long *age = (long *) ptr;

	decrypt_data(data, datalen, "purl", key, subkey);

	/* Expect at least a date*/
	if (datalen < 9) return false;

	/* Ignore purl relation records */
	if (!memcmp(data, "pkg:", 4)) return false;

	/* Extract created date (1st CSV field) from popularity record */
	char date[MAX_FIELD_LN] = "\0";
	extract_csv(date, (char *) data, 1, MAX_FIELD_LN);

	/* Expect date separators. Format 2009-03-21T22:32:25Z */
	if (date[4] != '-' || date[7] != '-') return false;

	/* Chop date string into year, month and day strings */
	date[4] = 0;
	date[7] = 0;
	date[10] = 0;

	/* Extract year */
	int year = atoi(date) - 1900;
	if (year < 0) return false;

	/* Extract year */
	int month = atoi(date + 5) - 1;
	if (month < 0) return false;

	/* Extract year */
	int day = atoi(date + 8);
	if (day < 0) return false;

	/* Fill time structure */
	struct tm t;
	time_t epoch;
	t.tm_year = year;
	t.tm_mon = month;
	t.tm_mday = day;
	t.tm_hour = 0;
	t.tm_min = 0;
	t.tm_sec = 0;
	t.tm_isdst = 0;
	epoch = mktime(&t);

	/* Keep the oldest date in case there are multiple sources */
	long seconds = (long) time (NULL) - (long) epoch;
	if (seconds > *age) *age = seconds;

	return false;
}

/**
 * @brief Return the age of a component in seconds
 * @param md5 Component md5
 * @return age in seconds
 */
int get_component_age(uint8_t *md5)
{
	if (!md5) return 0;

	/* Fetch record */
	long age = 0;

	if (ldb_table_exists(oss_purl.db, oss_purl.table)) //skip purl if the table is not present
		ldb_fetch_recordset(NULL, oss_purl, md5, false, handle_get_component_age, &age);

	return age;
}
/**
 * @brief Calculate the hash of purl@version
 * @param out[out] pointer to md5 hash
 * @param purl component purl string
 * @param version component version string
 */

void purl_version_md5(uint8_t *out, char *purl, char *version)
{
	char purl_version[MAX_ARGLN];
	sprintf(purl_version, "%s@%s", purl, version);
	MD5((uint8_t *)purl_version, strlen(purl_version), out);
}

