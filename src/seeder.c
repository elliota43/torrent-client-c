//
// Created by Elliot Anderson on 12/29/25.
//

#include "seeder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_RESET "\x1b[0m"

void broadcast_have(SharedState *state, int piece_idx) {
    uint32_t msg_len = htonl(5);
    uint8_t id = 4;
    uint32_t idx_net = htonl(piece_idx);

    unsigned char packet[9];
    memcpy(packet, &msg_len, 4);
    packet[4] = id;
    memcpy(packet + 5, &idx_net, 4);

    // Iterate over all active connections
    // Note: don't lock here, assume it is being called from the main thread loop
    for (int i = 0; i < state->max_connections; i++) {
        PeerContext *p = &state->connections[i];
        if (p->sock > 0 && p->state > PEER_STATE_HANDSHAKING) {
            // send blindly
            send(p->sock, packet, 9, 0);
        }
    }
}

void handle_peer_request(PeerContext *ctx, SharedState *state, uint32_t piece_idx, uint32_t begin, uint32_t len) {
    // Validation
    if (len > 16384 || piece_idx >= state->meta->num_pieces) return;

    // check if we have this piece
    pthread_mutex_lock(&state->lock);
    int status = state->piece_status[piece_idx];
    pthread_mutex_unlock(&state->lock);

    if (status != 2) return; // don't have

    // prepare buffer
    char *buffer = malloc(len);
    if (!buffer) return;

    // Read from disk
    long global_offset = (long)piece_idx * state->meta->piece_length + begin;
    long bytes_read = 0;

    while (bytes_read < len) {
        long current_pos = global_offset + bytes_read;
        long bytes_left = len - bytes_read;

        FileInfo *target_file = NULL;
        for (int i = 0; i < state->meta->num_files; i++) {
            long f_start = state->meta->files[i].global_offset;
            long f_end = f_start + state->meta->files[i].length;

            if (current_pos >= f_start && current_pos < f_end) {
                target_file = &state->meta->files[i];
                break;
            }
        }

        if (!target_file) break;

        long file_relative_offset = current_pos - target_file->global_offset;
        long space_in_file = target_file->length - file_relative_offset;
        long chunk_size = (bytes_left < space_in_file) ? bytes_left : space_in_file;

        FILE *f = fopen(target_file->path, "rb");
        if (f) {
            fseek(f, file_relative_offset, SEEK_SET);
            fread(buffer + bytes_read, 1, chunk_size, f);
            fclose(f);
        } else {
            free(buffer);
            return; // disk error
        }

        bytes_read += chunk_size;
    }

    // Construct PIECE Packet
    // Len(4) + ID(1) + Index(4) + Begin(4) + Data(N)
    uint32_t pkt_len = htonl(9 + len);
    uint8_t id = 7;
    uint32_t idx_net = htonl(piece_idx);
    uint32_t begin_net = htonl(begin);

    unsigned char *header = malloc(13 + len);
    memcpy(header, &pkt_len, 4);
    header[4] = id;
    memcpy(header + 5, &idx_net, 4);
    memcpy(header + 9, &begin_net, 4);
    memcpy(header + 13, buffer, len);

    // Send
    // @todo: check for EAGAIN/partial writes
    ssize_t sent = send(ctx->sock, header, 13 + len, 0);

    if (sent > 0) {
        // @todo: Log uploads to file
        printf(ANSI_COLOR_MAGENTA ">> Uploaded %d bytes to Peer %d\n" ANSI_COLOR_RESET, len, ctx->peer_idx);
    }

    free(buffer);
    free(header);
}