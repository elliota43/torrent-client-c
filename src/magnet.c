//
// Created by Elliot Anderson on 12/28/25.
//

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "magnet.h"

int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int parse_magnet_uri(const char *uri, unsigned char *out_hash) {
    const char *prefix = "xt=urn:btih:";
    const char *start = strstr(uri, prefix);

    if (!start) return 0; // not a valid magnet link
    start += strlen(prefix);

    // hash should be 40 hex characters
    for (int i = 0; i < 20; i++) {
        int high = hex_char_to_int(start[i * 2]);
        int low = hex_char_to_int(start[i * 2 + 1]);

        if (high == -1 || low == -1) return 0; // invalid hex

        out_hash[i] = (unsigned char)((high << 4) | low);
    }
    return 1;
}