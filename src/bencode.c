//
// Created by Elliot Anderson on 12/27/25.
//

#include "bencode.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

const char* parse_bencoded_string(const char *p, char **output_str) {
    // Parse the length (manual atoi)
    int len = 0;
    while (isdigit(*p)) {
        len = len * 10 + (*p - '0');
        p++;
    }

    // Check for colon separator
    if (*p != ':') {
        printf("Error: Expected ':'\n");
        return NULL;
    }
    p++; // Skip the ':'

    // Allocate memory and copy the string
    *output_str = malloc(len + 1);

    // Copy 'len' bytes from 'p' to the new string
    for (int i = 0; i < len; i++) {
        (*output_str)[i] = *p;
        p++; // advance pointer
    }
    (*output_str)[len] = '\0'; // Null-Terminate

    return p;

}

const char* parse_bencoded_int(const char *p, int *out_val) {
    // Check for start char 'i'
    if (*p != 'i') return NULL;
    p++; // Move past 'i'

    int num = 0;
    int sign = 1;

    if (*p == '-') {
        sign = -1;
        p++;
    }

    while (*p != 'e') {
        num = num * 10 + (*p - '0');
        p++;
    }

    if (*p != 'e') return NULL;
    p++;

    *out_val = num * sign;
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

        if (*p == 'i') {
            node->type = TORRENT_INT;
            p = parse_bencoded_int(p, &node->val.i);
        } else if (isdigit(*p)) {
            node->type = TORRENT_STRING;
            p = parse_bencoded_string(p, &node->val.s);
        } else if (*p == 'l') {
            node->type = TORRENT_LIST;
            p = parse_bencoded_list(p, &node->val.l);
        } else if (*p == 'd') {
            node->type = TORRENT_DICT;
            p = parse_bencoded_dict(p, &node->val.l);
        }

        if (head == NULL) {
            head = node;
        } else {
            curr->next = node;
        }
        curr = node;
    }

    p++;
    *out_list = head;
    return p;
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

        // Parse Value
        if (*p == 'i') {
            node->type = TORRENT_INT;
            p = parse_bencoded_int(p, &node->val.i);
        } else if (isdigit(*p)) {
            node->type = TORRENT_STRING;
            p = parse_bencoded_string(p, &node->val.s);
        } else if (*p == 'l') {
            node->type = TORRENT_LIST;
            p = parse_bencoded_list(p, &node->val.l);
        } else if (*p == 'd') {
            node->type = TORRENT_LIST;
            p = parse_bencoded_dict(p, &node->val.l);
        }

        if (head == NULL) head = node;
        else curr->next = node;
        curr = node;
    }

    p++; // skip 'e'
    *out_list = head;
    return p;
}
