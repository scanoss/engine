#ifndef __PARSE_H
    #define __PARSE_H

#include <stdint.h>


void extract_csv(char *out, char *in, int n, long limit);
void extract_csv(char *out, char *in, int n, long limit);

void lowercase(char *word);
char *skip_domain(char *url);
char *skip_first_comma(char *data);

#endif