#ifndef __REPORT_H
    #define __REPORT_H

#include "scanoss.h"
#include "match_list.h"

extern char kb_version[];

void json_open_file(char *filename);    
void json_close_file(void);
void report_open(scan_data_t *scan);
//void print_json_match(scan_data_t *scan, match_data match, int *match_counter);
bool print_json_match(match_data_t * match);
void print_json_nomatch(scan_data_t *scan);
void print_matches();
void json_open();
void json_close(void);
void kb_version_get(void);
#endif
