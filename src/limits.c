#include "limits.h"

/**
  * @file limits.c
  * @date 13 Dec 2020 
  * @brief Define general limits
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/limits.c
  */

int range_tolerance = 5;  /** A maximum number of non-matched lines tolerated inside a matching range */
int min_match_lines = 10; /** Minimum number of lines matched for a match range to be acepted */
int min_match_hits  = 4;  /** Minimum number of snippet ID hits to produce a snippet match*/
int fetch_max_files = 12000; /** Maximum number of files to fetch during component matching */

const int max_vulnerabilities = 50; /** Show only the first N vulnerabilities */