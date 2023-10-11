#include "limits.h"

/**
  * @file limits.c
  * @date 13 Dec 2020 
  * @brief Define general limits
 
  * //TODO Long description
  * @see https://github.com/scanoss/engine/blob/master/src/limits.c
  */


int consecutive_score = 4000;   /** Maximumm sUsed for snippet selection */

/* During snippet scanning, when a wfp (with more than consecutive_threshold wfps) produces a score higher 
   than consecutive_score by consecutive_hits in a row, the scan will skip consecutive_jump snippets */
int consecutive_hits = 4;       
int consecutive_jump = 5;      
int consecutive_threshold = 50; 

int range_tolerance = 5;  /** A maximum number of non-matched lines tolerated inside a matching range */
int min_match_lines = 10; /** Minimum number of lines matched for a match range to be acepted */
int min_match_hits  = 4;  /** Minimum number of snippet ID hits to produce a snippet match*/

const int max_vulnerabilities = 50; /** Show only the first N vulnerabilities */
