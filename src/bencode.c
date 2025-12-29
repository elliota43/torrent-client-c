//
// Created by Elliot Anderson on 12/27/25.
//
#include "bencode.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

const char* parse_bencoded_string(const char *p, char **output_str) {

    if (!isdigit(*p)) return NULL;

    char *endptr;
    long len = strtol(p, &endptr, 10);
    if (*endptr != ':') return NULL;

    const char *str_start = endptr + 1;
    *output_str = malloc(len + 1);
    strncpy(*output_str, str_start, len);
    (*output_str)[len] = '\0';

    return str_start + len;
}

const char* parse_bencoded_int(const char *p, int *out_val) {
    // Check for start char 'i'
    if (*p != 'i') return NULL;
    p++; // Move past 'i'

   char *endptr;
    *out_val = strtol(p, &endptr, 10);

    if (*endptr != 'e') return NULL;
    return endptr + 1;
}

// Generic Value Parser (for lists and dicts)
// parses one value and updates the node's type, value, start, and end.
const char* parse_value(const char *p, TorrentVal *node) {
    node->start = p;

    if (*p == 'i') {
        node->type = TORRENT_INT;
        p = parse_bencoded_int(p, &node->val.i);
    }
    else if (isdigit(*p)) {
        node->type = TORRENT_STRING;
        p = parse_bencoded_string(p, &node->val.s);
    }
    else if (*p == 'l') {
        node->type = TORRENT_LIST;
        p = parse_bencoded_list(p, &node->val.l);
    }
    else if (*p == 'd') {
        node->type = TORRENT_DICT;
        p = parse_bencoded_dict(p, &node->val.l);
    }
    else {
        return NULL; // invalid format
    }

    node->end = p;
    return p;
}

const char* parse_bencoded_list(const char *p, TorrentVal **out_list) {
    if (*p != 'l') return NULL;
    p++;

    TorrentVal *head = NULL;
    TorrentVal *curr = NULL;

    while (*p != 'e') {
        TorrentVal *node = malloc(sizeof(TorrentVal));
        node->next = NULL;
        node->key = NULL; // keys reserved for dicts

        p = parse_value(p, node);

        if (!p) {
            free(node);
            return NULL;
        }

        if (head == NULL) {
            head = node;
            curr = node;
        } else {
            curr->next = node;
            curr = curr;
            curr = node;
        }
    }
    *out_list = head;
    return p + 1;  // skip 'e'
}

const char* parse_bencoded_dict(const char *p, TorrentVal **out_list) {
    if (*p != 'd') return NULL;
    p++;

    TorrentVal *head = NULL;
    TorrentVal *curr = NULL;

    while (*p != 'e') {
        TorrentVal *node = malloc(sizeof(TorrentVal));
        node->next = NULL;

        // Parse key

        if (!isdigit(*p)) return NULL;

        p = parse_bencoded_string(p, &node->key);

        p = parse_value(p, node);

        if (!p) return NULL;

        if (head == NULL) {
            head = node;
            curr = node;
        } else {
            curr->next = node;
            curr = node;
        }
    }

    *out_list = head;
    return p + 1; // skip 'e'
}
