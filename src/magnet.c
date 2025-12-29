//
// Created by Elliot Anderson on 12/28/25.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "magnet.h"
#include "client_state.h"

// Helper to decode URL-encoded strings (e.g., %3A -> :)
void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16*a+b;
            src+=3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int parse_magnet_uri(const char *uri, TorrentMeta *meta) {
    // 1. Parse Info Hash (xt=urn:btih:...)
    const char *prefix = "xt=urn:btih:";
    const char *start = strstr(uri, prefix);

    if (!start) return 0; // Not a valid magnet link
    start += strlen(prefix);

    for (int i = 0; i < 20; i++) {
        int high = hex_char_to_int(start[i * 2]);
        int low = hex_char_to_int(start[i * 2 + 1]);

        if (high == -1 || low == -1) return 0; // Invalid hex

        meta->info_hash[i] = (unsigned char)((high << 4) | low);
    }

    // 2. Parse Tracker (tr=...)
    // Note: Magnets can have multiple 'tr', we just take the first one for now.
    const char *tr_start = strstr(uri, "tr=");
    if (tr_start) {
        tr_start += 3; // Skip "tr="
        const char *tr_end = strchr(tr_start, '&');

        int len = 0;
        if (tr_end) len = tr_end - tr_start;
        else len = strlen(tr_start);

        char *raw_url = malloc(len + 1);
        strncpy(raw_url, tr_start, len);
        raw_url[len] = '\0';

        // Decode (udp%3A%2F%2F -> udp://)
        meta->announce = malloc(len + 1);
        url_decode(meta->announce, raw_url);

        free(raw_url);
        printf("Magnet Tracker: %s\n", meta->announce);
    } else {
        // Fallback default if no tracker specified (rare)
        printf("No tracker found in magnet. Using default.\n");
        meta->announce = strdup("udp://tracker.opentrackr.org:1337");
    }

    return 1;
}