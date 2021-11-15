// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/psi.c
 *
 * Post-scan tasks
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
  * @file psi.c
  * @date 12 Jul 2020 
  * @brief //TODO
  
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/psi.c
  */

#include "psi.h"
#include "keywords.h"
#include "limits.h"
#include "url.h"

/**
 * @brief Meta post scanning function 
 * @param matches //TODO
 */
void post_scan(match_data *matches)
{
	if (!(engine_flags & DISABLE_BEST_MATCH))
	{
		/* Find best match based on component_hint */
		if (!select_best_match(matches))
		{
			/* Select best match from keyword analysis */
			bool selected = keyword_analysis(matches);

			/* Select preferred purl schema */
			if (!selected) select_best_url(matches);
		}
	}
}
