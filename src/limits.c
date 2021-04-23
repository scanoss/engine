#include "limits.h"

int scan_limit = 10;

int consecutive_score = 4000;
int consecutive_hits = 4;
int consecutive_jump = 5;
int consecutive_threshold = 50;

int range_tolerance = 5;  // A maximum number of non-matched lines tolerated inside a matching range
int min_match_lines = 10; // Minimum number of lines matched for a match range to be acepted
int min_match_hits  = 5;  // Minimum number of snippet ID hits to produce a snippet match

const int rank_items = 20; // Number of items to evaluate in component and path rankings

const int max_vulnerabilities = 50; // Show only the first N vulnerabilities
