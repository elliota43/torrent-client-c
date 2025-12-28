#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/sha.h>
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

    // Load file
    printf("Loading file: %s\n", argv[1]);
    long file_len;
    char *data = read_file(argv[1], &file_len);
    if (!data) return 1;

    // Parse Bencode
    TorrentVal *torrent_data = NULL;
    const char *end_ptr = parse_bencoded_dict(data, &torrent_data);

    if (!end_ptr) {
        printf("Parsing failed!\n");
        free(data);
        return 1;
    }

    printf("Successfully parsed the torrent file!\n");

    // Extract Info Hash & Announce URL
    TorrentVal *curr = torrent_data;
    char *final_announce_url = NULL;
    unsigned char info_hash[20];
    int have_info_hash = 0;

    while (curr != NULL) {
        if (curr->key && strcmp(curr->key, "announce") == 0) {
            final_announce_url = curr->val.s;
        }
        else if (curr->key && strcmp(curr->key, "info") == 0) {
            // Calculate SHA-1 Hash of the raw info dict
            long info_len = curr->end - curr->start;
            SHA_CTX ctx;
            SHA1_Init(&ctx);
            SHA1_Update(&ctx, (unsigned char*)curr->start, info_len);
            SHA1_Final(info_hash, &ctx);
            have_info_hash = 1;

            printf("Info Hash calculated: ");
            for (int i = 0; i < 20; i++) printf("%02x", info_hash[i]);
            printf("\n");
        }

        curr = curr->next;
    }

    if (final_announce_url && have_info_hash) {
        // --- DEBUG: FORCE OPENTRACKR (Since leechers-paradise is flaky) ---
        printf("DEBUG: Overriding tracker URL with OpenTrackr...\n");
        final_announce_url = "udp://tracker.opentrackr.org:1337";
        // ------------------------------------------------------------------

        printf("Tracker URL: %s\n", final_announce_url);

        // Parse tracker URL
        TrackerUrl *t = parse_tracker_url(final_announce_url);
        printf("Host: %s | Port: %d | Type: %s\n",
            t->host, t->port, (t->protocol == TRACKER_UDP) ? "UDP" : "HTTP");

        // Resolve DNS
        struct sockaddr_in tracker_addr;
        if (get_tracker_addr(t, &tracker_addr) == 0) {
            unsigned char *ip = (unsigned char *)&tracker_addr.sin_addr.s_addr;
            printf("Resolved IP: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);

            srand(time(NULL));

            if (t->protocol == TRACKER_UDP) {
                int64_t conn_id = -1;
                int sock = -1;

                // UDP Handshake (Connect)
                for (int i = 0; i < 5; i++) {
                    printf("Attempt %d of 5...\n", i + 1);
                    conn_id = udp_announce_connect(&tracker_addr, &sock);
                    if (conn_id != -1) break;
                }

                if (conn_id != -1) {
                    printf("Handshake success! Connection ID: %lld\n", conn_id);

                    // UDP Announce (Get Peers)
                    PeerInfo *peers = NULL;
                    int peer_count = udp_announce_request(sock, &tracker_addr, conn_id, info_hash, &peers);

                    if (peer_count > 0) {
                        printf("----------------------------------------\n");
                        printf("SUCCESS: Found %d Peers!\n", peer_count);

                        // Print up to 10 peers
                        for (int k = 0; k < peer_count && k < 10; k++) {
                            unsigned char *pip = (unsigned char *)&peers[k].ip;
                            uint16_t pport = ntohs(peers[k].port);
                            printf("Peer %d: %d.%d.%d.%d : %d\n", k+1, pip[0], pip[1], pip[2], pip[3], pport);
                        }
                        printf("----------------------------------------\n");
                        free(peers);
                    } else {
                        printf("Announce failed or returned 0 peers.\n");
                    }

                    close(sock); // clean up socket
                } else {
                    printf("Failed to connect after 5 attempts.\n");
                }

            } else {
                printf("Skipping UDP Handshake (Protocol is HTTP)\n");
            }
        }
        free_tracker_url(t);
    } else {
        printf("Error: Missing 'announce' key or failed to calculate Info Hash.\n");
    }

    free(data);
    // TODO: Free the torrent_data tree properly
    return 0;
}

