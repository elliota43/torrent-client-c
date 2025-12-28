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
#include "peer.h"

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

// helper to ensure we received exactly 'len' bytes. returns 0 on success, -1 on failure
int recv_exact(int sock, void *buf, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t r = recv(sock, (char*)buf + received, len - received, 0);
        if (r <= 0) return -1;
        received += r;
    }
    return 0;
}


int main(int argc, char *argv[]) {
    if (argc != 2 ) {
        printf("Usage: %s <file.torrent>\n", argv[0]);
        return 1;
    }

    // ==============================================
    // Parse Torrent File
    // ==============================================
    printf("Loading file: %s\n", argv[1]);
    long file_len;
    char *data = read_file(argv[1], &file_len);
    if (!data) return 1;

    TorrentVal *torrent_data = NULL;
    const char *end_ptr = parse_bencoded_dict(data, &torrent_data);
    if (!end_ptr) {
        printf("Parsing Failed!\n");
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
        } else if (curr->key && strcmp(curr->key, "info") == 0) {
            long info_len = curr->end - curr->start;
            SHA_CTX ctx;
            SHA1_Init(&ctx);
            SHA1_Update(&ctx, (unsigned char *)curr->start, info_len);
            SHA1_Final(info_hash, &ctx);
            have_info_hash = 1;

            printf("Info Hash calculated: ");
            for (int i = 0; i < 20; i++) printf("%02x", info_hash[i]);
            printf("\n");
        }
        curr = curr->next;
    }

    if (!final_announce_url || !have_info_hash) {
        printf("Error: Missing 'announce' or 'info' section.\n");
        free(data);
        return 1;
    }

    // ==================================================
    // Tracker (UDP)
    // ==================================================

    // DEBUG: force opentrackr for reliability
    printf("DEBUG: Overriding tracker URL with OpenTrackr...\n");
    final_announce_url = "udp://tracker.opentrackr.org:1337";

    TrackerUrl *t = parse_tracker_url(final_announce_url);
    printf("Tracker: %s:%d\n", t->host, t->port);

    struct sockaddr_in tracker_addr;
    if (get_tracker_addr(t, &tracker_addr) != 0) {
        printf("DNS Resolution failed.\n");
        return 1;
    }

    int sock = -1;
    int64_t conn_id = -1;
    srand(time(NULL));

    // Handshake
    for (int i = 0; i < 3; i++) {
        printf("Tracker Handshake Attempt %d...\n", i + 1);
        conn_id = udp_announce_connect(&tracker_addr, &sock);
        if (conn_id != -1) break;
    }

    if (conn_id == -1) {
        printf("Tracker Handshake failed.\n");
        return 1;
    }
    printf("Tracker Handshake Scucess! ID: %lld\n", conn_id);

    // Announce (Get Peers)
    PeerInfo *peers = NULL;
    int peer_count = udp_announce_request(sock, &tracker_addr, conn_id, info_hash, &peers);
    close(sock);

    if (peer_count <= 0) {
        printf("No peers found.\n");
        return 1;
    }

    printf("Found %d peers.\n", peer_count);

    // ===================================================
    // Connect to a Peer (TCP)
    // ===================================================

    int peer_sock = -1;
    char my_id[21];
    int download_complete = 0;
    sprintf(my_id, "-TC0001-%012d", rand());

    printf("Hunting for active peers (Timeout 2s)...\n");

    for (int i = 0; i < peer_count && i < 50; i++) {

        if (download_complete) break;

        // skip duplicates
        if (i > 0 && peers[i].ip == peers[i-1].ip) continue;

        printf("\n[Attempt %d] ", i);
        int peer_sock = connect_to_peer(&peers[i], info_hash, my_id);

        if (peer_sock == -1) {
            continue;
        }

        printf("   >>> Sending 'Interested'...\n");
        unsigned char interested[] = {0, 0, 0, 1, 2};
        send(peer_sock, interested, 5, 0);

        int is_choked = 1; // track state so we don't spam requests

        while (1) {
            uint32_t msg_len_net;
            if (recv(peer_sock, &msg_len_net, 4, MSG_WAITALL) <= 0) {
                printf(" --- Peer disconnected --- \n");
                break;
            }
            uint32_t msg_len = ntohl(msg_len_net);

            if (msg_len == 0) {
                printf("   <<< Keep-Alive\n");
                continue;
            }

            uint8_t msg_id;
            if (recv_exact(peer_sock, &msg_id, 1) != 0) {
                printf(" --- Error reading ID --- \n");
                break;
            }

            uint32_t payload_len = msg_len - 1;

            if (msg_id == 0) {
                printf("   <<< Choke\n");
                is_choked = 1;
            }
            else if (msg_id == 1) {
                printf("   <<< Unchoke!\n");
                is_choked = 0;
            }
            else if (msg_id == 4) {
                printf("   <<< Have Piece Index: ");
                // Read 4 bytes index, but just ignore it for now todo
                char buf[4];
                recv_exact(peer_sock, buf, 4);

                payload_len = 0;
                printf("(Ignored)\n");
            }
            else if (msg_id == 5) {
                printf("   <<< Bitfield (Size: %c)\n", payload_len);
                // standard bittorrent clients send this first
                // just skip and assume they have piece 0
            }
            else if (msg_id == 7) {
                printf("   <<< PIECE RECEIEVED! \n");

                // Read Header
                char header[8];
                recv(peer_sock, header, 8, MSG_WAITALL);

                // Read Data
                uint32_t data_size = payload_len - 8;
                char *buf = malloc(data_size);
                recv(peer_sock, buf, data_size, MSG_WAITALL);

                printf("   DOWNLOAD SUCCESS! (Size: %d bytes)\n", data_size);

                // verify the first few bytes (should be non-zero)
                printf("   First 4 bytes: %02X %02X %02X %02X\n",
                    (unsigned char)buf[0], (unsigned char)buf[1],
                    (unsigned char)buf[2], (unsigned char)buf[3]);

                free(buf);
                download_complete = 1;
                break;
            }
            else {
                printf("   <<< Message ID %d (Length %d)\n", msg_id, payload_len);
            }

            if (payload_len > 0) {
                char *trash = malloc(payload_len);
                recv_exact(peer_sock, trash, payload_len);
                free(trash);
            }

            // REQUEST DATA if we are unchoked and if we havent already
            // ask immediately every loop iteration we are unchoked
            if (!is_choked && !download_complete) {
                printf("   >>> Sending Request (Piece 0)...\n");


                // Request Piece 0
                uint32_t req_len = htonl(13);
                uint8_t req_id = 6;
                uint32_t idx = htonl(0);
                uint32_t begin = htonl(0);
                uint32_t len = htonl(16384);

                unsigned char req[17];
                memcpy(req, &req_len, 4);
                memcpy(req + 4, &req_id, 1);
                memcpy(req + 5, &idx, 4);
                memcpy(req + 9, &begin, 4);
                memcpy(req + 13, &len, 4);
                if (send(peer_sock, req, 17, 0) < 0) {
                    printf(" --- Send Failed ---\n");
                    break;
                }

                // sleep 1 sec so we don't spam the peer 1000 times a second while waiting
                // for the piece message to arive
                sleep(1);
            }
        }
        close(peer_sock); // cleanup socket before moving to next peer
    }

    free(peers);
    free(data);

    if (download_complete) {
        printf("\nProgram finished successfully.\n");
        return 0;
    } else {
        printf("\nExhausted all peers. No download occurred.\n");
        return 1;
    }
}

