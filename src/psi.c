// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/psi.c
 *
 * Post-scan tasks
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

bool skip_file_path(uint8_t *file_record, int filerec_ln, match_data *matches)
{
	return false;
}

/* Perform additional post-scan tasks */
void post_scan(match_data *matches)
{
}

