// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/lock.c
 *
 * DB Locking mechanisms
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

bool ldb_locked()
{
	return ldb_file_exists (ldb_lock_path);
}

/* Lock LDB for writing */
void ldb_lock()
{
	if (ldb_locked()) ldb_error ("E051 Concurrent ldb writing not supported (/dev/shm/ldb.lock exists)");
	pid_t pid = getpid();

	/* Write lock file */
	FILE *lock = fopen (ldb_lock_path, "wb");
	if (!fwrite (&pid, 4, 1, lock)) printf("Warning: cannot write lock file\n");
	fclose (lock);

	/* Validate lock file */
	lock = fopen (ldb_lock_path, "rb");
	if (!fread (&pid, 4, 1, lock)) printf("Warning: cannot read lock file\n");
	fclose (lock);

	if (pid != getpid()) ldb_error ("E052 Concurrent ldb writing is not supported. (check /dev/shm/ldb.lock)");
}

/* Unlock LDB */
void ldb_unlock()
{
	unlink(ldb_lock_path);
}

