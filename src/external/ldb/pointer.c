// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/pointer.c
 *
 * Pointer handling functions
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

/* Returns the map position for the given record ID, using only the last 3 bytes
   of the key, since the sector name contains the first byte */
uint64_t ldb_map_pointer_pos(uint8_t *key)
{

	uint64_t out = 0;

	/* Obtain a nuclear "char" pointer to the uint32 */
	uint8_t *k = (uint8_t *) &out;

	/* Assign less significant bytes (inverting for easy debugging, so that 00 00 01 is the second position in the map)*/
	k[0]=key[3];
	k[1]=key[2];
	k[2]=key[1];

	return out * ldb_ptr_ln;
}

/* Return pointer to the beginning of the given list */
uint64_t ldb_list_pointer(FILE *ldb_sector, uint8_t *key)
{
	fseeko64(ldb_sector, ldb_map_pointer_pos(key), SEEK_SET);
	return ldb_uint40_read(ldb_sector);
}

/* Return pointer to the last node of the list */
uint64_t ldb_last_node_pointer(FILE *ldb_sector, uint64_t list_pointer)
{
	if (list_pointer == 0) return 0;
	fseeko64(ldb_sector, list_pointer, SEEK_SET);
	return ldb_uint40_read(ldb_sector);
}

/* Update list pointers */
void ldb_update_list_pointers(FILE *ldb_sector, uint8_t *key, uint64_t list, uint64_t new_node)
{
	/* If this is the first node of the list, we update the map and leave */
	if (list == 0)
	{
		fseeko64(ldb_sector, ldb_map_pointer_pos(key), SEEK_SET);
		ldb_uint40_write(ldb_sector, new_node);
		if (new_node < ldb_sector_map_size) ldb_error("E054 Data corruption");
	}

	/* Otherwise we update the list */
	else
	{

		/* Get the current last node pointer */
		fseeko64(ldb_sector, list, SEEK_SET);
		uint64_t last_node = ldb_uint40_read(ldb_sector);

		if (last_node < ldb_sector_map_size) {
			printf("\nMap size is %lu\n", ldb_sector_map_size);
			printf ("\nData corruption on list %lu for key %02x%02x%02x%02x with last node %lu < %lu\n", list, key[0], key[1], key[2], key[3], last_node, ldb_sector_map_size);
			ldb_error("E055 Data corruption");
		}

		/* Update the list pointer to the new last node */
		fseeko64(ldb_sector, list, SEEK_SET);
		ldb_uint40_write(ldb_sector, new_node);


		/* Update the last node pointer to next (new) node */
		fseeko64(ldb_sector, last_node, SEEK_SET);
		ldb_uint40_write(ldb_sector, new_node);

	}
}

void ldb_list_unlink(FILE *ldb_sector, uint8_t *key)
{
	fseeko64(ldb_sector, ldb_map_pointer_pos(key), SEEK_SET);
	ldb_uint40_write(ldb_sector, 0);
}

