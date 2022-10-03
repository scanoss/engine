#ifndef __REPORT_H
    #define __REPORT_H

#include "scanoss.h"
#include "match_list.h"

extern char kb_version[];

void json_open_file(char *filename, char* report);    
void json_close_file(scan_data_t * scan, char * report);
void report_open(scan_data_t *scan, char * report);
bool print_json_match(match_data_t * match, char *report);
void print_json_nomatch(scan_data_t *scan, char * report);
void print_server_stats(scan_data_t *scan, char * report);
void json_open(char * report);
void json_close(char * report);
void kb_version_get(void);
#endif
