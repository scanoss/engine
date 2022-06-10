#include "hpsm.h"
#include <string.h>
#include "util.h"

bool hpsm_enabled;
struct ranges hpsm_result;
/* HPSM - Normalized CRC8 for each line */
char *hpsm_crc_lines = NULL;

/* HPSM function pointers */
char *(*hpsm_hash_file_contents)(char *data);
struct ranges (*hpsm)(char *data, char *md5);
struct ranges (*hpsm_process)(unsigned char *data, int length, char *md5);

bool hpsm_calc(uint8_t *file_md5)
{
    if (!hpsm_enabled)
        return true;

    char *file = md5_hex(file_md5);
    hpsm_result = hpsm(hpsm_crc_lines, file);
    free(file);

    if (memcmp(hpsm_result.matched, "0%%", 2))
        return true;

    return false;
}

struct ranges hpsm_get_result()
{
    return hpsm_result;
}
