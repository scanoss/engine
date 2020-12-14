#include "scanoss.h"

const char *matchtypes[] = {"none", "component", "file", "snippet"};
//const char *license_sources[] = {"component_declared", "file_spdx_tag", "file_header"};
const char *copyright_sources[] = {"component_declared", "file_header"};
//const char *vulnerability_sources[] = {"nvd", "github_advisories"};
//const char *quality_sources[] = {"best_practices"};
const char *dependency_sources[] = {"component_declared"};

bool match_extensions = false;
int report_format = plain;

bool first_file = true;

char *sbom = NULL;
char *blacklisted_assets = NULL;

char SCANOSS_VERSION[7] = "4.0.3";

