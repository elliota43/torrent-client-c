#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include "bencode.h"
#include "tracker.h"
#include "peer.h"

#define BLOCK_SIZE 16384

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

// helper to ensure we received exactly 'len' bytes
int recv_exact(int sock, void *buf, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t r = recv(sock, (char*)buf + received, len - received, 0);
        if (r <= 0) return -1;
        received += r;
    }
    return 0;
}

// Helper: Find Key in Dict
TorrentVal* find_key(TorrentVal *dict, const char *key) {
    TorrentVal *curr = dict;
    while (curr) {
        if (curr->key && strcmp(curr->key, key) == 0) return curr;
        curr = curr->next;
    }
    return NULL;
}

// Verify piece hash against expected hash
int verify_piece_hash(const unsigned char *data, size_t data_len, const unsigned char *expected_hash) {
    unsigned char computed_hash[20];
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, data_len);
    SHA1_Final(computed_hash, &ctx);
    return memcmp(computed_hash, expected_hash, 20) == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2 ) {
        printf("Usage: %s <file.torrent>\n", argv[0]);
        return 1;
    }

    // ==============================================
    // Parse Torrent File
    // ==============================================
    printf("Loading Torrent Metadata: %s\n", argv[1]);
    long torrent_len;
    char *data = read_file(argv[1], &torrent_len);
    if (!data) return 1;

    TorrentVal *torrent_data = NULL;
    parse_bencoded_dict(data, &torrent_data);

    // Get info dict
    TorrentVal *info = NULL;
    TorrentVal *curr = torrent_data;

    while (curr) {
        if (strcmp(curr->key, "info") == 0) info = curr;
        curr = curr->next;
    }

    if (!info) { printf("Error: no info dict.\n"); return 1; }

    // ==============================================
    // CALCULATE FILE SIZE (Single or Multi-File)
    // ==============================================
    long file_size = 0;
    TorrentVal *t_length = find_key(info->val.l, "length");

    if (t_length) {
        // Single File Mode
        file_size = t_length->val.i;
        printf("Mode: Single File\n");
    } else {
        // Multi File Mode: Sum up all file lengths
        printf("Mode: Multi File\n");
        TorrentVal *files = find_key(info->val.l, "files");
        if (files) {
            TorrentVal *file_item = files->val.l; // List of file dicts
            while (file_item) {
                // Each item is a Dict. Find "length" inside it.
                TorrentVal *f_len = find_key(file_item->val.l, "length");
                if (f_len) {
                    file_size += f_len->val.i;
                }
                file_item = file_item->next;
            }
        }
    }

    TorrentVal *t_piece_len = find_key(info->val.l, "piece length");
    TorrentVal *t_pieces = find_key(info->val.l, "pieces");

    if (!file_size || !t_piece_len || !t_pieces) {
        printf("Error: Could not determine file size or piece length.\n");
        return 1;
    }

    long piece_length = t_piece_len->val.i;
    long num_pieces = (file_size + piece_length - 1) / piece_length;

    // extract piece hashes (each piece has a 20 byte SHA1 hash)
    //const char *pieces_str = t_pieces->val.s;
    char *raw_ptr = t_pieces->start;

    while (isdigit(*raw_ptr)) raw_ptr++;

    if (*raw_ptr == ':') raw_ptr++;

    const char *pieces_str = raw_ptr;

    // verify length
    long pieces_raw_len = t_pieces->end - pieces_str;
    if (pieces_raw_len < num_pieces * 20) {
        printf("Error: pieces string too short in file.\n");
        return 1;
    }

    printf("Total Size:   %ld bytes\n", file_size);
    printf("Piece Length: %ld bytes\n", piece_length);
    printf("Total Blocks: %ld\n", (file_size + BLOCK_SIZE - 1) / BLOCK_SIZE);

    // ==============================================
    // Calculate Info Hash
    // ==============================================
    unsigned char info_hash[20];
    long info_len = info->end - info->start;
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, (unsigned char*)info->start, info_len);
    SHA1_Final(info_hash, &ctx);

    // ==================================================
    // Tracker (UDP)
    // ==================================================
    printf("DEBUG: Overriding tracker URL with OpenTrackr...\n");
    TrackerUrl *t_url = parse_tracker_url("udp://tracker.opentrackr.org:1337");

    struct sockaddr_in tracker_addr;
    get_tracker_addr(t_url, &tracker_addr);

    int sock = -1;
    int64_t conn_id = -1;
    srand(time(NULL));

    // Handshake
    for (int i = 0; i < 3; i++) {
        conn_id = udp_announce_connect(&tracker_addr, &sock);
        if (conn_id != -1) break;
    }

    if (conn_id == -1) {
        printf("Tracker Handshake failed.\n");
        return 1;
    }
    printf("Tracker Handshake Success! ID: %lld\n", conn_id);

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
    // Download Engine
    // ===================================================

    FILE *outfile = fopen("sintel_final.mp4", "wb");
    if (!outfile) { perror("Error opening output file"); return 1; }

    // track which pieces we have downloaded and verified
    int *pieces_complete = calloc(num_pieces, sizeof(int));
    long total_downloaded = 0;
    char my_id[21];
    sprintf(my_id, "-TC0001-%012d", rand());

    // --- NEW: Track where we are in the peer list so we don't reset to 0 ---
    int current_peer_idx = 0;

    while (total_downloaded < file_size) {

        // Find next piece to download
        long piece_index = -1;
        for (long i = 0; i < num_pieces; i++) {
            if (!pieces_complete[i]) {
                piece_index = i;
                break;
            }
        }

        if (piece_index == -1) {
            printf("All pieces downloaded!\n");
            break;
        }

        printf("\n>>> Downloading Piece %ld/%ld (%.2f%% complete)\n", 
        piece_index + 1, num_pieces, (double)total_downloaded / file_size * 100);


        // Calculate piece size (last piece may be smaller)
        long piece_size = piece_length;
        if (piece_index == num_pieces - 1) {
            piece_size = file_size - (piece_index * piece_length);
        }

        // Allocate buffer for entire piece
        char *piece_data = malloc(piece_size);
        if (!piece_data) {
            printf("Memory allocation failed!\n");
            break;
        }

        int piece_downloaded = 0;
        int attempts = 0;

        // Try to download this piece from peers
        while (!piece_downloaded && attempts < peer_count * 2) {
            int peer_sock = -1;
            int peer_attempts = 0;

            // Find a working peer
            while (peer_sock == -1 && peer_attempts < peer_count) {
                int idx = (current_peer_idx + peer_attempts) % peer_count;
                if (peers[idx].ip == 0) {
                    peer_attempts++;
                    continue;
                }

                printf("   Connecting to peer %d...", idx);
                peer_sock = connect_to_peer(&peers[idx], info_hash, my_id);

                if (peer_sock == -1) {
                    peers[idx].ip = 0;
                } else {
                    current_peer_idx = (idx + 1) % peer_count;
                }

                peer_attempts++;
            }

            if (peer_sock == -1) {
                printf("  No available peers. Waiting 2s...\n");
                sleep(2);
                attempts++;
                continue;
            }

            printf("Connected! Sending 'Interested'...\n");
            unsigned char interested[] = {0, 0, 0, 1, 2};
            send(peer_sock, interested, 5, 0);

            int is_choked = 1;
            long piece_bytes_received = 0;

            int block_request_sent = 0;

            // Download piece in blocks
            while (piece_bytes_received < piece_size) {
                // send request if unchoked
                if (!is_choked && !block_request_sent && piece_bytes_received < piece_size) {
                    long block_offset = piece_bytes_received;
                    long block_size = BLOCK_SIZE;
                    if (block_offset + block_size > piece_size) {
                        block_size = piece_size - block_offset;
                    }

                    uint32_t req_len = htonl(13);
                    uint8_t req_id = 6;
                    uint32_t idx = htonl(piece_index);
                    uint32_t begin = htonl(block_offset);
                    uint32_t len = htonl(block_size);

                    unsigned char req[17];
                    memcpy(req, &req_len, 4);
                    memcpy(req + 4, &req_id, 1);
                    memcpy(req + 5, &idx, 4);
                    memcpy(req + 9, &begin, 4);
                    memcpy(req + 13, &len, 4);

                    if (send(peer_sock, req, 17, 0) < 0) {
                        printf("   Send failed, disconnecting...\n");
                        break;
                    }
                    block_request_sent = 1;
                }

                // Receive Message
                uint32_t msg_len_net;
                if (recv_exact(peer_sock, &msg_len_net, 4) != 0) {
                    printf("   Connection lost.\n");
                    break;
                }

                uint32_t msg_len = ntohl(msg_len_net);

                if (msg_len == 0) {
                    continue; // Keep-Alive
                }

                uint8_t msg_id;
                if (recv_exact(peer_sock, &msg_id, 1) != 0) {
                    printf("   Error reading message ID.\n");
                    break;
                }
                uint32_t payload_len = msg_len - 1;

                if (msg_id == 0) {
                    is_choked = 1;
                } else if (msg_id == 1) {
                    is_choked = 0;
                } else if (msg_id == 5) {
                    // Bitfield -- skip
                    if (payload_len > 0) {
                        char *trash = malloc(payload_len);
                        recv_exact(peer_sock, trash, payload_len);
                        free(trash);
                    }
                } else if (msg_id == 7) {
                    // Piece message
                    char header[8];
                    if (recv_exact(peer_sock, header, 8) != 0 ) {
                        printf("   Error reading piece header.\n");
                        break;
                    }

                    uint32_t recv_piece_idx = ntohl(*(uint32_t*)&header[0]);
                    uint32_t recv_offset = ntohl(*(uint32_t*)&header[4]);

                    if (recv_piece_idx != piece_index || recv_offset != piece_bytes_received) {
                        printf("   Warning: Unexpected piece index or offset.  Discarding...\n");
                        // Skip the data
                        uint32_t data_size = payload_len - 8;
                        char *trash = malloc(data_size);
                        recv_exact(peer_sock, trash, data_size);
                        free(trash);
                        continue;
                    }

                    uint32_t data_size = payload_len - 8;

                    if (recv_exact(peer_sock, piece_data + piece_bytes_received, data_size) != 0) {
                        printf("   Error receiving piece data.\n");
                        break;
                    }

                    piece_bytes_received += data_size;
                    block_request_sent = 0; // reset flag so we can request the next block
                    if (piece_bytes_received > 0 && piece_bytes_received % BLOCK_SIZE == 0) {
                        printf(".");
                        fflush(stdout);
                    }
                } else {
                    // Other message -- skip payload
                    if (payload_len > 0) {
                        char *trash = malloc(payload_len);
                        recv_exact(peer_sock, trash, payload_len);
                        free(trash);
                    }
                }

                // Check if piece is complete
                if (piece_bytes_received >= piece_size) {
                    // verify piece hash
                    const unsigned char *expected_hash = (const unsigned char*)(pieces_str + piece_index * 20);
                    if (verify_piece_hash((unsigned char*)piece_data, piece_size, expected_hash)) {
                        printf("\n Piece %ld verified!\n", piece_index);

                        fseek(outfile, piece_index * piece_length, SEEK_SET);

                        fwrite(piece_data, 1, piece_size, outfile);
                        fflush(outfile);
                        pieces_complete[piece_index] = 1;
                        total_downloaded += piece_size;
                        piece_downloaded = 1;
                    } else {
                        printf("\n Piece %ld verification failed. Re-downloading...\n", piece_index);
                        piece_bytes_received = 0; // reset to re-download
                    }
                    break;
                }
            }

            close(peer_sock);
            if (!piece_downloaded) {
                attempts++;
            }
        }

        free(piece_data);

        if (!piece_downloaded) {
            printf("   Failed to download piece %ld after multiple attempts.\n", piece_index);
            break;
        }
    }

    fclose(outfile);
    free(pieces_complete);
    free(peers);
    free(data);

    if (total_downloaded >= file_size) {
        printf("\n\n ---- Download Complete! ----\n");
        printf("File saved as: sintel_final.mp4\n");
        printf("Total Downloaded: %ld bytes.\n", total_downloaded);
        return 0;
    } else {
        printf("\n\n ---- Download Failed! ----\n");
        printf("Downloaded: %ld / %ld bytes.\n", total_downloaded, file_size);
        return 1;
    }
}