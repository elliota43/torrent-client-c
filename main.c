#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include "bencode.h"
#include "tracker.h"

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

    char *final_announce_url = NULL;

    while (curr != NULL) {
        if (curr->key && strcmp(curr->key, "announce") == 0) {
            printf("--------------------------------------------------\n");
            printf("TRACKER URL FOUND: %s\n", curr->val.s);
            printf("--------------------------------------------------\n");

            final_announce_url = curr->val.s;
            found = 1;
        }
        else if (curr->key) {
            printf("Found key: %s\n", curr->key);
        }

        curr = curr->next;
    }

    if (found && final_announce_url != NULL) {
        printf("Tracker URL: %s\n", final_announce_url);

        // Parse
        TrackerUrl *t = parse_tracker_url(final_announce_url);
        printf("Host: %s | Port: %d | Type: %s\n", t->host, t->port, (t->protocol == TRACKER_UDP) ? "UDP" : "HTTP");

        // Resolve DNS
        struct sockaddr_in tracker_addr;
        if (get_tracker_addr(t, &tracker_addr) == 0) {

            unsigned char *ip = (unsigned char *)&tracker_addr.sin_addr.s_addr;
            printf("Resolved IP: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);

            srand(time(NULL)); // seed random # generator

            if (t->protocol == TRACKER_UDP) {
                int64_t conn_id = -1;
                for (int i = 0; i < 5; i++) {
                    printf("Attempt %d of 5...\n", i + 1);
                    conn_id = udp_announce_connect(&tracker_addr);
                    if (conn_id != -1) break;
                }
            } else {
                printf("Skipping UDP handshake (Protocol is HTTP)\n");
            }
        }

        free_tracker_url(t);
    }

    // TODO: write a function to free the 'torrent_data' tree
    return 0;
}

