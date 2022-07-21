
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
  * @file decrypt.c
  * @date 19 July 2022 
  * @brief Contains the functions used for the LDB decryptation (if it is encrypted).
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/decrypt.c
  */

#include <stdint.h>
#include "scanoss.h"
#include "debug.h"
#include "decrypt.h"

char * (*decrypt_data) (uint8_t *data, uint32_t size, char *table, uint8_t *key, uint8_t *subkey);
void  (*decrypt_mz) (uint8_t *data, uint32_t len);
/**
 * @brief Decrypt data function pointer. Will be executed for the ldb_fetch_recordset function in each iteration. See LDB documentation for more details.
 * @param data //TODO  
 * @param size //TODO
 * @param table //TODO
 * @param key //TODO
 * @param subkey //TODO
 */
char * standalone_decrypt_data(uint8_t *data, uint32_t size, char *table, uint8_t *key, uint8_t *subkey)
{
	char * msg = NULL;
  
  if (!strcmp(table, "file"))
    msg = strndup((char*) data + 16, size - 16);
  else
    msg = strndup((char*) data, size);
  
  return msg;

}
