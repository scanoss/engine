#ifndef __PARSE_H
    #define __PARSE_H

#include <stdint.h>
#include <stdbool.h>
#include "scanoss.h"
#include "component.h"

void extract_csv(char *out, char *in, int n, long limit);
void lowercase(char *word);
char *skip_domain(char *url);
char *skip_first_comma(char *data);
char *skip_first_slash(char *data);
bool is_file(char *path);
component_item *get_components(char *filepath);

#endif
