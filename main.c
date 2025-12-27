#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "bencode.h"

char* read_file(const char* filename, long* out_len) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("Failed to open file");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    *out_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(*out_len + 1);
    if (!buf) return NULL;

    fread(buf, 1, *out_len, f);
    fclose(f);

    buf[*out_len] = '\0';
    return buf;
}



int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: %s <file.torrent>\n", argv[0]);
        return 1;
    }

    // 1. Load File
    printf("Loading file: %s\n", argv[1]);
    long file_len;
    char *data = read_file(argv[1], &file_len);

    if (!data) {
        return 1;
    }

    // Parse bencode

    // Root of a torrent file is always a dictionary
    TorrentVal *torrent_data = NULL;
    const char *end_ptr = parse_bencoded_dict(data, &torrent_data);

    if (!end_ptr) {
        printf("Parsing failed! The file might be corrupted or not valid bencode.\n");
        free(data);
        return 1;
    }
    printf("Successfully parsed the torrent file!\n");

    // Find the "announce" key
    TorrentVal *curr = torrent_data;
    int found = 0;
    while (curr != NULL) {
        if (curr->key && strcmp(curr->key, "announce") == 0) {
            printf("--------------------------------------------------\n");
            printf("TRACKER URL FOUND: %s\n", curr->val.s);
            printf("--------------------------------------------------\n");
            found = 1;
        }
        else if (curr->key) {
            printf("Found key: %s\n", curr->key);
        }

        curr = curr->next;
    }

    if (!found) {
        printf("Warning: No 'announce' key found.\n");
    }

    // TODO: write a function to free the 'torrent_data' tree
    free(data);
    return 0;
}