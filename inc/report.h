#ifndef __REPORT_H
    #define __REPORT_H

#include "scanoss.h"
#include "match_list.h"

extern char kb_version[];

void json_open_file(char *filename);    
void json_close_file(scan_data_t * scan);
void report_open(scan_data_t *scan);
bool print_json_match(match_data_t * match);
void print_json_nomatch(scan_data_t *scan);
void print_server_stats(scan_data_t *scan);
void json_open();
void json_close(void);
void kb_version_get(void);
bool print_json_component(component_data_t * component);
#endif
