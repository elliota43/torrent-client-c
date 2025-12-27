//
// Created by Elliot Anderson on 12/27/25.
//

#ifndef TORRENT_BENCODE_H
#define TORRENT_BENCODE_H

typedef enum { TORRENT_INT, TORRENT_STRING, TORRENT_LIST, TORRENT_DICT } Type;

typedef struct TorrentVal {
    Type type;
    char *key; // stores the dictionary key (NULL if inside a List)
    union {
        int i;
        char *s;
        struct TorrentVal *l; // Head of a list or dict items
    } val;
    struct TorrentVal *next;
} TorrentVal;

// Function Prototypes
const char* parse_bencoded_dict(const char *p, TorrentVal **out_list);
const char* parse_bencoded_list(const char *p, TorrentVal **out_list);
const char* parse_bencoded_string(const char *p, char **output_str);
const char* parse_bencoded_int(const char *p, int *out_val);
void free_torrent_val(TorrentVal *val);

#endif //TORRENT_BENCODE_H