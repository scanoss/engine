#ifndef __ATTRIBUTIONS_H
    #define __ATTRIBUTIONS_H

#include "scanoss.h"

int attribution_notices(char *sbom);
char *parse_sbom(char *filepath, bool load_vendor, bool load_component, bool load_purl);

#endif
