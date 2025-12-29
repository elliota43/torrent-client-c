#include "metadata.h"
#include "peer.h"
#include "bencode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>

#define METADATA_BLOCK_SIZE 16384

// Debug helper
void print_debug_payload(char *data, int len) {
    printf("      [RAW] ");
    for (int i = 0; i < len && i < 60; i++) {
        unsigned char c = data[i];
        if (isprint(c)) printf("%c", c);
        else printf(".");
    }
    printf("\n");
}

void send_ext_handshake(int sock) {
    // We declare our ID for ut_metadata is 1
    char *payload = "d1:md11:ut_metadatai1eee";
    uint32_t len = strlen(payload);
    uint32_t len_net = htonl(len + 2);

    char packet[1024];
    memcpy(packet, &len_net, 4);
    packet[4] = 20;
    packet[5] = 0;
    memcpy(packet + 6, payload, len);

    send(sock, packet, len + 6, 0);
}

void send_metadata_request(int sock, int ut_metadata_id, int piece) {
    char payload[100];
    sprintf(payload, "d8:msg_typei0e5:piecei%dee", piece);
    uint32_t len = strlen(payload);
    uint32_t len_net = htonl(len + 2);

    char packet[1024];
    memcpy(packet, &len_net, 4);
    packet[4] = 20;
    packet[5] = ut_metadata_id;
    memcpy(packet + 6, payload, len);

    send(sock, packet, len + 6, 0);
    printf("   [Meta] >> Sent Request for Piece %d (ExtID: %d)\n", piece, ut_metadata_id);
}

TorrentVal* find_key_recursive(TorrentVal *dict, const char *key) {
    TorrentVal *curr = dict;
    while (curr) {
        if (curr->key && strcmp(curr->key, key) == 0) return curr;
        if (curr->val.l && (curr->type == TORRENT_DICT || curr->type == TORRENT_LIST)) {
             TorrentVal *found = find_key_recursive(curr->val.l, key);
             if (found) return found;
        }
        curr = curr->next;
    }
    return NULL;
}

char* fetch_metadata_from_peer(PeerInfo *peer, unsigned char *info_hash, char *my_id, long *out_len) {
    int sock = connect_to_peer(peer, info_hash, my_id);
    if (sock == -1) return NULL;

    struct timeval timeout = {15, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    unsigned char interested[] = {0, 0, 0, 1, 2};
    send(sock, interested, 5, 0);

    send_ext_handshake(sock);

    int ut_metadata_id = -1;
    long metadata_size = 0;
    long total_pieces = 0;
    char *metadata_buf = NULL;
    long bytes_collected = 0;
    int success = 0;
    int *pieces_received = NULL;

    while (!success) {
        uint32_t len_net;
        ssize_t res = recv(sock, &len_net, 4, 0);
        if (res <= 0) break;

        uint32_t len = ntohl(len_net);
        if (len == 0) continue;

        unsigned char id;
        recv(sock, &id, 1, 0);

        if (id != 20) {
            char trash[16384];
            long to_drain = len - 1;
            while (to_drain > 0) {
                ssize_t r = recv(sock, trash, (to_drain > 16384 ? 16384 : to_drain), 0);
                if (r <= 0) break;
                to_drain -= r;
            }
            continue;
        }

        // --- EXTENSION MESSAGE ---
        unsigned char ext_id;
        recv(sock, &ext_id, 1, 0);

        uint32_t payload_len = len - 2;
        char *payload = malloc(payload_len + 1);

        long r = 0;
        while(r < payload_len) {
            ssize_t chunk = recv(sock, payload + r, payload_len - r, 0);
            if (chunk <= 0) break;
            r += chunk;
        }
        payload[payload_len] = 0;

        // printf("   [Meta] << Recv Ext Msg (ExtID: %d, Len: %d)\n", ext_id, payload_len);

        if (ext_id == 0) {
            // HANDSHAKE RESPONSE
            TorrentVal *root = NULL;
            parse_bencoded_dict(payload, &root);

            TorrentVal *m_dict = find_key_recursive(root, "m");
            if (m_dict) {
                TorrentVal *ut_val = find_key_recursive(m_dict->val.l, "ut_metadata");
                if (ut_val) ut_metadata_id = ut_val->val.i;
            }

            TorrentVal *size_val = find_key_recursive(root, "metadata_size");
            if (size_val) metadata_size = size_val->val.i;

            if (ut_metadata_id > 0 && metadata_size > 0) {
                printf("   [Meta] Handshake OK! Size: %ld\n", metadata_size);

                total_pieces = (metadata_size + METADATA_BLOCK_SIZE - 1) / METADATA_BLOCK_SIZE;
                if (pieces_received) free(pieces_received);
                pieces_received = calloc(total_pieces, sizeof(int));

                if (metadata_buf) free(metadata_buf);
                metadata_buf = malloc(metadata_size);

                for (int i = 0; i < total_pieces; i++) {
                    send_metadata_request(sock, ut_metadata_id, i);
                }
            }
        }
        else if (ext_id == 1) {
            // DATA PIECE (ID 1 is what WE declared for ut_metadata)

            if (strstr(payload, "msg_typei2e")) {
                printf("   [Meta] Peer Rejected Request.\n");
                free(payload);
                break;
            }

            int piece_idx = -1;
            char *ptr = strstr(payload, "piecei");
            if (ptr) piece_idx = atoi(ptr + 6);

            char *raw_start = strstr(payload, "ee");
            if (raw_start) {
                raw_start += 2;
                long header_len = raw_start - payload;
                long data_len = payload_len - header_len;

                if (piece_idx >= 0 && piece_idx < total_pieces) {
                    long offset = piece_idx * METADATA_BLOCK_SIZE;
                    if (offset + data_len <= metadata_size) {
                        memcpy(metadata_buf + offset, raw_start, data_len);

                        if (!pieces_received[piece_idx]) {
                            pieces_received[piece_idx] = 1;
                            bytes_collected += data_len;
                            // printf("   [Meta] Saved Piece %d (%ld bytes)\n", piece_idx, data_len);
                        }

                        if (bytes_collected >= metadata_size) {
                            printf("   [Meta] Metadata Complete!\n");
                            *out_len = metadata_size;
                            success = 1;
                        }
                    }
                }
            }
        }
        free(payload);
    }

    if (pieces_received) free(pieces_received);
    close(sock);
    if (!success && metadata_buf) { free(metadata_buf); metadata_buf = NULL; }

    return metadata_buf;
}