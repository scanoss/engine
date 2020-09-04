// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/node.c
 *
 * LDB node handling routines
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


 * NODE STRUCTURE
 * Every data list starts with a pointer to the last node in the list, followed by the first node:

 * List header:
 * LN = is the 40-bit pointer to the last node

 * Node header:
 * Each node starts with a pointer to the next node, followed by the node size, followed by the node data
 * NN = is the 40-bit pointer to the next node
 * TS = is the 16-bit (or 32-bit) total size of the node data (in bytes, if variable-sized records, in number of records if fixed-sized records)
 * K = is the remaining part of the key for the group of records that follow (in case the key is bigger than 32-bit, otherwise K is omitted)
 * GS = is the total size of the group records that follow (those sharing K, omitted when key is 32-bit)

 * Node data is a series of records (size+data):
 * R: Data record
 * s = is a 16-bit record size (omitted when record size is fixed)
 * d = is the data record
 */

void ldb_load_node_header(struct ldb_recordset *rs, uint8_t *header)
{

	/* Load next node and node length */
	rs->next_node  = uint40_read(header);
	rs->node_ln    = uint16_read(header + 5);

	/* When records are fixed in length, node size is expressed in number of records */
	if (rs->rec_ln) rs->node_ln = rs->rec_ln * rs->node_ln;
}

void ldb_load_node(struct ldb_recordset *rs)
{
	if (rs->node) free(rs->node);

	/* Read node */
	rs->node = malloc(rs->node_ln + 1);
	if (!fread(rs->node, 1, rs->node_ln, rs->sector)) printf("Warning: cannot load node\n");

	/* Terminate with a chr(0) */
	rs->node[rs->node_ln] = 0;

}

/*
   Writes a data node and updates pointers
   */
void ldb_node_write (struct ldb_table table, FILE *ldb_sector, uint8_t *key, uint8_t *data, uint32_t dataln, uint16_t records)
{
	uint8_t subkey_ln = table.key_ln - LDB_KEY_LN;

	/* Check that record length is within bounds */
	if (dataln > LDB_MAX_NODE_LN) ldb_error ("E053 Data record size exceeded");

	if (!records) if (dataln + LDB_PTR_LN + LDB_PTR_LN + table.ts_ln >= LDB_MAX_NODE_LN)
		ldb_error ("E053 Data record size exceeded");

	/* Obtain the pointer to the last node of the list */
	uint64_t list = ldb_list_pointer(ldb_sector, key);

	if (list > 0 && list < LDB_MAP_SIZE) {
		printf("\nFatal data corruption on list %lu for key %02x%02x%02x%02x\n", list, key[0], key[1], key[2], key[3]);
		fprintf(stdout, "E057 Map location %08lx\n", ldb_map_pointer_pos(key));
		exit(EXIT_FAILURE);
	}

	/* Seek end of file, and save the pointer to the new node */
	fseeko64(ldb_sector, 0, SEEK_END);
	uint64_t new_node = ftello64(ldb_sector);

	if (new_node < LDB_MAP_SIZE) {
		fprintf(stdout, "E056 Data sector corrupted, with %lu below map_size\n", new_node);
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for new node, plus LN(5), NN(5) and TS(4 max)*/
	uint8_t *node = malloc(LDB_MAX_NODE_LN + LDB_PTR_LN + LDB_PTR_LN + table.ts_ln);
	uint64_t node_ptr = 0;

	/* LN: A new list starts with a pointer to the last node (which is itself after LN(5)) */
	if (list == 0)
	{
		uint40_write(node, new_node + LDB_PTR_LN);
		node_ptr = LDB_PTR_LN;
	}

	/* NN: Node starts with a zeroed "next" pointer, since it will be the last in the list */
	uint40_write(node + node_ptr, 0);
	node_ptr += LDB_PTR_LN;

	/* TS: Write the node length (either number of records (fixed-recln) or number of bytes (variable_recln)) */
	if (table.ts_ln == 2)
	{
		if (records) uint16_write(node + node_ptr, records);
		else uint16_write(node + node_ptr, dataln + subkey_ln);
		node_ptr += 2;
	}
	else if (table.ts_ln == 4)
	{
		if (records) uint32_write(node + node_ptr, records);
		else uint32_write(node + node_ptr, dataln + subkey_ln);
		node_ptr += 4;
	}
	else ldb_error("E060 Unsupported node_length size (must be 2 or 4 bytes)");

	/* K: Write the key after the 4th byte (if needed) */
	if (table.key_ln > LDB_KEY_LN)
	{
		memcpy(node + node_ptr, key + LDB_KEY_LN, table.key_ln - LDB_KEY_LN);
		node_ptr += (table.key_ln - LDB_KEY_LN);
	}

	/* R: Write the data */
	memcpy(node + node_ptr, data, dataln);
	node_ptr += dataln;

	/* Write actual node */
	if (node_ptr != fwrite(node, 1, node_ptr, ldb_sector)) ldb_error("E058 Error writing node");

	/* Update list pointers */
	ldb_update_list_pointers(ldb_sector, key, list, new_node);

	free(node);
}

/*
   Reads a node from the given location (ptr) for a 32-bit key. If ptr is set to zero, the location is
   obtained from the sector map. The function returns a pointer to the next node, which is zero if it 
   is the last node in the list.
   */
uint64_t ldb_node_read(uint8_t *sector, struct ldb_table table, FILE *ldb_sector, uint64_t ptr, uint8_t *key, uint32_t *bytes_read, uint8_t **out, int max_node_size)
{
	*bytes_read = 0;

	/* If pointer is zero, get the list location from the map */
	if (ptr == 0)
	{
		/* Read sector pointer either from disk (ldb_sector) or memory (sector) */
		if (sector)
			ptr = uint40_read(sector + ldb_map_pointer_pos(key));
		else
			ptr = ldb_list_pointer(ldb_sector, key);

		/* If pointer is zero, then there are no records for the key */
		if (ptr == 0) { return 0; }

		/* If there is a list, we skip the first bytes (LN: last node pointer) to move into the first node */
		ptr += LDB_PTR_LN;
	}

	uint8_t *buffer;

	/* Read node information into buffer: NN(5) and TS(2/4) */
	if (sector) buffer = sector + ptr;
	else
	{
		fseeko64(ldb_sector, ptr, SEEK_SET);
		buffer = calloc(LDB_PTR_LN + table.ts_ln + LDB_KEY_LN, 1);
		if (!fread(buffer, 1, LDB_PTR_LN + table.ts_ln, ldb_sector)) printf("Warning: cannot read LDB node\n");
	}

	/* NN: Obtain the next node */
	uint64_t next_node = uint40_read(buffer);

	/* TS: Obtain the size of the node */
	uint32_t node_size = 0;
	if (table.ts_ln == 2) node_size = uint16_read(buffer + LDB_PTR_LN);
	else node_size = uint32_read(buffer + LDB_PTR_LN);

	uint32_t actual_size = node_size;

	/* When records are fixed in length, node size is expressed in number of records */
	if (table.rec_ln) actual_size = node_size * table.rec_ln;

	/* If the node size exceeds the wanted limit, then ignore it entirely */
	if (max_node_size) if (actual_size > max_node_size) actual_size = 0;

	/* A deleted node will have a size set to zero. */
	if (actual_size)
	{

		if (table.rec_ln) if (actual_size > 64800) actual_size = 64800; //TODO: EXPAND?

		/* Return the entire node */
		if (sector)
		{
			*out = buffer + LDB_PTR_LN + table.ts_ln;
		}
		else
		{
			if (!fread(*out, 1, actual_size, ldb_sector)) printf("Warning: cannot read entire LDB node\n");
		}
		*bytes_read = actual_size;

		/* Gracefully terminate non-fixed records (strings) with a chr(0) */
		if (!sector) if (table.rec_ln == 0) *(*out+actual_size) = 0;
	}

	if (!sector) free(buffer);
	return next_node;
}

/* 
   Unlinks a first node found for the given table and key
   */
void ldb_node_unlink (struct ldb_table table, uint8_t *key)
{

	uint16_t subkeyln = table.key_ln - LDB_KEY_LN;

	/* Open sector */
	FILE *ldb_sector = ldb_open(table, key, "r+");

	if (ldb_sector)
	{

		/* For a 32-bit key, we simply wipe out the map pointer, killing the entire list */
		if (table.key_ln == LDB_KEY_LN)
		{
			/* Move pointer to the map pointer */
			fseeko64(ldb_sector, ldb_map_pointer_pos(key), SEEK_SET);

			/* Set pointer to zero */
			ldb_uint40_write(ldb_sector, 0);
		}

		/* A key greater than 32-bit will require reading the entire list and searching every node for matching subkeys */
		else
		{

			/* If pointer is zero, then there are no records for the key */
			uint64_t next = ldb_list_pointer(ldb_sector, key);

			if (next)
			{
				/* Skip the first bytes (LN: last node pointer) to move into the first node */
				next += LDB_PTR_LN;

				do
				{
					uint64_t last = next;

					/* Move the file pointer */
					fseeko64(ldb_sector, next, SEEK_SET);

					/* Read node information into buffer: NN(5) and TS(2/4) */
					uint8_t *buffer = malloc(LDB_PTR_LN + table.ts_ln + table.key_ln);
					if (!fread(buffer, 1, LDB_PTR_LN + table.ts_ln, ldb_sector))
					{
						printf("Warning: cannot read LDB node info\n");
						break;
					}

					/* NN: Obtain the next node */
					next = uint40_read(buffer);

					/* TS: Obtain the size of the node */
					uint16_t node_size = uint16_read(buffer + LDB_PTR_LN);

					/* When records are fixed in length, node size is expressed in number of records */
					if (table.rec_ln) node_size = node_size * table.rec_ln;

					/* A deleted node will have a size set to zero. */

					if (node_size != 0)
					{

						uint64_t node_ptr = 0;

						do
						{
							/* K: Compare the remaining part of the key */
							bool key_ok = true;
							uint16_t gs = node_size;
							uint64_t last_key = node_ptr;
							uint32_t get_bytes = subkeyln + (table.rec_ln ? 0 : 2);

							/* Read K and GS (2) if needed */
							if (!fread(buffer, 1, get_bytes, ldb_sector))
							{
								printf("Warning: cannot read LDB node info (K/GS)\n");
								break;
							}

							if (memcmp(buffer, key + LDB_KEY_LN, subkeyln) != 0) key_ok = false;

							if (key_ok)
							{
								if (!table.rec_ln)
								{
									/* Read and write GS if needed */
									gs = uint16_read(buffer + subkeyln);
									node_ptr += 2;
								}

								/* Move pointer back to the subkey and wipe it */
								fseeko64(ldb_sector, last + last_key + LDB_PTR_LN + table.ts_ln, SEEK_SET);
								uint8_t *empty_key = calloc(subkeyln , 1);
								fwrite(empty_key, 1, subkeyln, ldb_sector);
								free(empty_key);

								/* We leave after deleting */
								node_ptr = node_size;

							}
							else fseeko64(ldb_sector, last + LDB_PTR_LN + table.ts_ln + get_bytes + gs + (table.rec_ln ? 0 : 2), SEEK_SET);
							node_ptr += gs;	

						} while (node_ptr < node_size);
					}

					free(buffer);
				} while (next);
			}
		}
	}

	if (ldb_sector) fclose(ldb_sector);
}

bool ldb_validate_node(uint8_t *node, uint32_t node_size, int subkey_ln)
{

	/* Make sure we have enough bytes in the node */
	if (node_size < (subkey_ln + 2)) return false;

	/* Extract datasets from node */
	uint32_t node_ptr = 0;
	while (node_ptr < node_size)
	{

		/* Skip subkey */
		node_ptr += subkey_ln;

		/* Get dataset size */
		int dataset_size = uint16_read(node + node_ptr);
		node_ptr += 2;

		/* Is the reported dataset_size greater than the remaining node? Then fail */
		if (node_ptr + dataset_size > node_size) return false;

		/* Extract records from dataset */
		if (subkey_ln)
		{
			uint32_t dataset_ptr = 0;
			while (dataset_ptr < dataset_size)
			{

				/* Get record size */
				int record_size = uint16_read(node + node_ptr + dataset_ptr);
				dataset_ptr += 2;

				/* Is the reported record_size greater than the remaining dataset? Then fail */
				if (node_ptr + dataset_ptr + record_size > node_size) return false;

				/* Move pointer to end of record */
				dataset_ptr += record_size;

				/* If we passed the dataset_size, the node is bad */
				if (dataset_ptr > dataset_size) return false;
			}
		}
		/* Move pointer to end of dataset */
		node_ptr += dataset_size;
	}
	return true;
}

