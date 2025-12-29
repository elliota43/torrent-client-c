//
// Created by Elliot Anderson on 12/28/25.
//

#include "async_downloader.h"
#include "peer.h"
#include "bitfield.h"
#include "connection_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <openssl/sha.h>
#include <arpa/inet.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define BLOCK_SIZE 16384
#define MAX_PIPELINE 10
#define CONNECTION_TIMEOUT 30

// --- Helpers ---

static void set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

static ssize_t recv_partial(int sock, void *buf, size_t len) {
    return recv(sock, buf, len, 0);
}

static void update_peer_have(PeerContext *ctx, int piece_idx, int total_pieces) {
    if (!ctx->bitfield) {
        ctx->bitfield_len = (total_pieces + 7) / 8;
        ctx->bitfield = calloc(ctx->bitfield_len, 1);
    }
    int byte_idx = piece_idx / 8;
    int bit_idx = 7 - (piece_idx % 8);
    if (byte_idx < ctx->bitfield_len) {
        ctx->bitfield[byte_idx] |= (1 << bit_idx);
    }
}

// --- Protocol Logic ---

static int send_handshake(PeerContext *ctx, unsigned char *info_hash, char *my_id) {
    char handshake[68];
    handshake[0] = 19;
    memcpy(handshake + 1, "BitTorrent protocol", 19);
    memset(handshake + 20, 0, 8);
    handshake[25] |= 0x10;
    memcpy(handshake + 28, info_hash, 20);
    memcpy(handshake + 48, my_id, 20);

    ssize_t sent = send(ctx->sock, handshake, 68, 0);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    return sent == 68 ? 1 : 0;
}

static int process_handshake_response(PeerContext *ctx, unsigned char *info_hash) {
    if (ctx->recv_pos < 68) {
        ssize_t n = recv_partial(ctx->sock, ctx->recv_buff + ctx->recv_pos, 68 - ctx->recv_pos);
        if (n <= 0) {
            if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) return -1;
            return 0;
        }
        ctx->recv_pos += n;
        if (ctx->recv_pos < 68) return 0;
    }

    if (memcmp(ctx->recv_buff + 28, info_hash, 20) != 0) return -1;

    ctx->recv_pos = 0;
    ctx->msg_len_expected = 0;
    ctx->state = PEER_STATE_IDLE;
    return 1;
}

static int send_request(PeerContext *ctx, int piece_idx, long offset, long length) {
    uint32_t req_len = htonl(13);
    uint8_t req_id = 6;
    uint32_t idx = htonl(piece_idx);
    uint32_t begin = htonl(offset);
    uint32_t len = htonl(length);

    unsigned char req[17];
    memcpy(req, &req_len, 4);
    memcpy(req + 4, &req_id, 1);
    memcpy(req + 5, &idx, 4);
    memcpy(req + 9, &begin, 4);
    memcpy(req + 13, &len, 4);

    ssize_t sent = send(ctx->sock, req, 17, 0);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    // Debug print restricted to once per piece start to avoid spam
    if (offset == 0) {
        printf(ANSI_COLOR_BLUE ">> Requesting Piece %d from Peer %d\n" ANSI_COLOR_RESET, piece_idx, ctx->peer_idx);
    }
    return sent == 17 ? 1 : 0;
}

static int verify_and_save_piece(PeerContext *ctx, SharedState *state) {
    TorrentMeta *meta = state->meta;
    int piece_idx = ctx->current_piece_idx;

    long piece_size = meta->piece_length;
    if (piece_idx == meta->num_pieces - 1) {
        piece_size = meta->file_size - (piece_idx * meta->piece_length);
    }

    if (ctx->piece_position < piece_size) return 0;

    const unsigned char *expected = (const unsigned char*)(meta->pieces_concat + piece_idx * 20);
    unsigned char computed[20];
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, (unsigned char*)ctx->temp_piece_buffer, piece_size);
    SHA1_Final(computed, &sha_ctx);

    if (memcmp(computed, expected, 20) != 0) {
        printf(ANSI_COLOR_RED "Hash mismatch piece %d\n" ANSI_COLOR_RESET, piece_idx);
        pthread_mutex_lock(&state->lock);
        state->piece_status[piece_idx] = 0;
        pthread_mutex_unlock(&state->lock);

        ctx->piece_position = 0;
        ctx->piece_bytes_received = 0;
        ctx->request_offset = 0;
        ctx->pending_requests = 0;
        return 0;
    }

    long global_offset = piece_idx * meta->piece_length;
    long bytes_written = 0;

    while (bytes_written < piece_size) {
        long current_global_pos = global_offset + bytes_written;
        long bytes_left = piece_size - bytes_written;

        FileInfo *target_file = NULL;
        for (int i = 0; i < meta->num_files; i++) {
            long f_start = meta->files[i].global_offset;
            long f_end = f_start + meta->files[i].length;
            if (current_global_pos >= f_start && current_global_pos < f_end) {
                target_file = &meta->files[i];
                break;
            }
        }

        if (!target_file) break;

        long file_offset = current_global_pos - target_file->global_offset;
        long space_in_file = target_file->length - file_offset;
        long chunk_size = (bytes_left < space_in_file) ? bytes_left : space_in_file;

        FILE *f = fopen(target_file->path, "r+b");
        if (!f) f = fopen(target_file->path, "wb");
        if (f) {
            fseek(f, file_offset, SEEK_SET);
            fwrite(ctx->temp_piece_buffer + bytes_written, 1, chunk_size, f);
            fclose(f);
        }
        bytes_written += chunk_size;
    }

    pthread_mutex_lock(&state->lock);
    state->piece_status[piece_idx] = 2; // DONE
    state->pieces_done_count++;
    pthread_mutex_unlock(&state->lock);

    free(ctx->temp_piece_buffer);
    ctx->temp_piece_buffer = NULL;
    ctx->current_piece_idx = -1;
    ctx->piece_position = 0;
    ctx->request_offset = 0;
    ctx->pending_requests = 0;

    return 1;
}

static int assign_piece(PeerContext *ctx, SharedState *state) {
    TorrentMeta *meta = state->meta;
    int piece_idx = -1;

    pthread_mutex_lock(&state->lock);
    for (int i = 0; i < meta->num_pieces; i++) {
        if (state->piece_status[i] == 0) {
            if (ctx->bitfield && !has_piece(ctx->bitfield, ctx->bitfield_len, i)) continue;

            piece_idx = i;
            state->piece_status[i] = 1;
            break;
        }
    }
    pthread_mutex_unlock(&state->lock);

    if (piece_idx == -1) return 0;

    long piece_size = meta->piece_length;
    if (piece_idx == meta->num_pieces - 1) {
        piece_size = state->meta->file_size - (piece_idx * state->meta->piece_length);
    }

    ctx->current_piece_idx = piece_idx;
    ctx->temp_piece_buffer = malloc(piece_size);
    ctx->piece_position = 0;
    ctx->piece_bytes_received = 0;
    ctx->request_offset = 0;
    ctx->pending_requests = 0;
    ctx->state = PEER_STATE_DOWNLOADING;
    return 1;
}

static int process_peer_messages(PeerContext *ctx, SharedState *state) {
    while (1) {
        if (ctx->msg_len_expected == 0) {
            if (ctx->recv_pos < 4) {
                ssize_t n = recv_partial(ctx->sock, ctx->recv_buff + ctx->recv_pos, 4 - ctx->recv_pos);
                if (n <= 0) {
                    if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) return -1;
                    return 0;
                }
                ctx->recv_pos += n;
                if (ctx->recv_pos < 4) return 0;
            }

            uint32_t msg_len_net = *(uint32_t*)ctx->recv_buff;
            ctx->msg_len_expected = ntohl(msg_len_net);

            if (ctx->msg_len_expected == 0) {
                ctx->recv_pos = 0;
                continue;
            }
            if (ctx->msg_len_expected > 32000) {
                printf(ANSI_COLOR_RED "Error: Message too large (%d)\n" ANSI_COLOR_RESET, ctx->msg_len_expected);

                return -1;
            }
        }

        size_t total_needed = 4 + ctx->msg_len_expected;
        if (ctx->recv_pos < total_needed) {
            ssize_t n = recv_partial(ctx->sock, ctx->recv_buff + ctx->recv_pos, total_needed - ctx->recv_pos);
            if (n <= 0) {
                if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) return -1;
                return 0;
            }
            ctx->recv_pos += n;
            if (ctx->recv_pos < total_needed) return 0;
        }

        uint8_t msg_id = ctx->recv_buff[4];
        uint32_t payload_len = ctx->msg_len_expected - 1;

        if (msg_id == 0) {
            ctx->am_choked = 1;
        }
        else if (msg_id == 1) {
            printf(ANSI_COLOR_GREEN "<< Peer %d UNCHOKED us! (Ready to download)\n" ANSI_COLOR_RESET, ctx->peer_idx);
            ctx->am_choked = 0;
        }
        else if (msg_id == 4) { // HAVE
            uint32_t piece = ntohl(*(uint32_t*)(ctx->recv_buff + 5));
            update_peer_have(ctx, piece, state->meta->num_pieces);
        }
        else if (msg_id == 5) { // BITFIELD
            if (ctx->bitfield) free(ctx->bitfield);
            ctx->bitfield = malloc(payload_len);
            ctx->bitfield_len = payload_len;
            memcpy(ctx->bitfield, ctx->recv_buff + 5, payload_len);
        }
        else if (msg_id == 7) { // PIECE
            if (ctx->state == PEER_STATE_DOWNLOADING) {
                uint32_t piece_idx = ntohl(*(uint32_t*)(ctx->recv_buff + 5));
                uint32_t begin = ntohl(*(uint32_t*)(ctx->recv_buff + 9));
                uint32_t data_len = payload_len - 8;

                if (piece_idx == ctx->current_piece_idx) {
                    long piece_size = state->meta->piece_length;
                    if (ctx->current_piece_idx == state->meta->num_pieces - 1)
                        piece_size = state->meta->file_size - (ctx->current_piece_idx * state->meta->piece_length);

                    if (begin + data_len <= piece_size && ctx->temp_piece_buffer) {
                        memcpy(ctx->temp_piece_buffer + begin, ctx->recv_buff + 13, data_len);
                        if (begin + data_len > ctx->piece_position) ctx->piece_position = begin + data_len;
                        ctx->piece_bytes_received += data_len;
                        ctx->pending_requests--;

                        pthread_mutex_lock(&state->lock);
                        state->total_bytes_downloaded += data_len;
                        pthread_mutex_unlock(&state->lock);
                    }
                }
            }
        }

        ctx->recv_pos = 0;
        ctx->msg_len_expected = 0;
    }
}

int start_async_download(SharedState *state, char *my_id) {
    TorrentMeta *meta = state->meta;
    fd_set read_fds, write_fds;
    struct timeval timeout;
    time_t now;

    // 1. Init Connections
    for (int i = 0; i < state->max_connections; i++) {
        PeerContext *ctx = &state->connections[i];
        if (ctx->sock > 0) {
            set_nonblocking(ctx->sock);
            ctx->state = PEER_STATE_HANDSHAKING;
            ctx->recv_pos = 0;
            ctx->msg_len_expected = 0;
            ctx->am_choked = 1;
            ctx->am_interested = 0;
            ctx->current_piece_idx = -1;
            ctx->last_activity = time(NULL);

            int res = send_handshake(ctx, meta->info_hash, my_id);
            if (res == -1) {
                close(ctx->sock);
                ctx->sock = -1;
            }
        }
    }

    printf("Starting async download loop...\n");

    while (1) {
        pthread_mutex_lock(&state->lock);
        int done = (state->pieces_done_count >= meta->num_pieces);
        pthread_mutex_unlock(&state->lock);
        if (done) break;

        // --- REPLENISH LOGIC ---
        int active_count = 0;
        for(int i=0; i<state->max_connections; i++) {
            if(state->connections[i].sock > 0) active_count++;
        }

        if (active_count < 5) {
            int needed = state->max_connections - active_count;
            ConnectedPeer *new_conns = malloc(needed * sizeof(ConnectedPeer));
            int found = scan_peers_async(state->peers, state->peer_count, new_conns, needed);

            if (found > 0) {
                int added = 0;
                for(int i=0; i<state->max_connections && added < found; i++) {
                    if (state->connections[i].sock <= 0) {
                        PeerContext *ctx = &state->connections[i];
                        ctx->sock = new_conns[added].sock;
                        ctx->peer_idx = new_conns[added].peer_idx;
                        set_nonblocking(ctx->sock);
                        ctx->state = PEER_STATE_HANDSHAKING;
                        ctx->recv_pos = 0;
                        ctx->msg_len_expected = 0;
                        ctx->am_choked = 1;
                        ctx->am_interested = 0;
                        ctx->bitfield = NULL;
                        ctx->current_piece_idx = -1;
                        ctx->temp_piece_buffer = NULL;
                        ctx->last_activity = time(NULL);

                        if (send_handshake(ctx, meta->info_hash, my_id) == -1) {
                            close(ctx->sock);
                            ctx->sock = -1;
                        }
                        added++;
                    }
                }
            }
            free(new_conns);
        }

        // --- PRE-SELECT WORK ASSIGNMENT ---
        // This is the Critical Fix: Assign work BEFORE select so write_fds is set correctly
        for(int i=0; i<state->max_connections; i++) {
            PeerContext *ctx = &state->connections[i];
            if (ctx->sock > 0 && ctx->state == PEER_STATE_IDLE) {
                if (assign_piece(ctx, state)) {
                    ctx->state = PEER_STATE_DOWNLOADING;
                }
            }
        }

        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        int max_fd = 0;
        now = time(NULL);

        for (int i = 0; i < state->max_connections; i++) {
            PeerContext *ctx = &state->connections[i];
            if (ctx->sock <= 0) continue;

            if (now - ctx->last_activity > CONNECTION_TIMEOUT) {
                close(ctx->sock);
                ctx->sock = -1;
                if(ctx->temp_piece_buffer) {
                    free(ctx->temp_piece_buffer);
                    ctx->temp_piece_buffer = NULL;
                }
                if(ctx->current_piece_idx != -1) {
                     pthread_mutex_lock(&state->lock);
                     state->piece_status[ctx->current_piece_idx] = 0;
                     pthread_mutex_unlock(&state->lock);
                }
                continue;
            }

            FD_SET(ctx->sock, &read_fds);

            // Check if we need to write
            if (ctx->state == PEER_STATE_HANDSHAKING ||
               (ctx->state == PEER_STATE_DOWNLOADING && !ctx->am_choked && ctx->pending_requests < MAX_PIPELINE)) {
                FD_SET(ctx->sock, &write_fds);
            }
            if (ctx->sock > max_fd) max_fd = ctx->sock;
        }

        if (max_fd == 0) {
            sleep(1);
            continue;
        }

        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        int ret = select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout);

        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < state->max_connections; i++) {
            PeerContext *ctx = &state->connections[i];
            if (ctx->sock <= 0) continue;

            if (FD_ISSET(ctx->sock, &read_fds)) {
                ctx->last_activity = now;
                if (ctx->state == PEER_STATE_HANDSHAKING) {
                    int res = process_handshake_response(ctx, meta->info_hash);
                    if (res == 1) {
                        unsigned char interested[] = {0, 0, 0, 1, 2};
                        send(ctx->sock, interested, 5, 0);
                        ctx->am_interested = 1;
                    } else if (res == -1) {
                        close(ctx->sock);
                        ctx->sock = -1;
                        continue;
                    }
                } else {
                    // process regular messages
                    if (process_peer_messages(ctx, state) < 0) {
                        // connection error
                        close(ctx->sock);
                        ctx->sock = -1;

                        if(ctx->temp_piece_buffer) {
                            free(ctx->temp_piece_buffer);
                            ctx->temp_piece_buffer = NULL;
                        }
                        if(ctx->current_piece_idx != -1) {
                             pthread_mutex_lock(&state->lock);
                             state->piece_status[ctx->current_piece_idx] = 0;
                             pthread_mutex_unlock(&state->lock);
                        }
                        continue;
                    }
                }
            }

            if (FD_ISSET(ctx->sock, &write_fds)) {
                if (ctx->state == PEER_STATE_DOWNLOADING && !ctx->am_choked) {
                    long piece_size = meta->piece_length;
                    if (ctx->current_piece_idx == meta->num_pieces - 1)
                        piece_size = meta->file_size - (ctx->current_piece_idx * meta->piece_length);

                    while (ctx->pending_requests < MAX_PIPELINE && ctx->request_offset < piece_size) {
                        long block_size = BLOCK_SIZE;
                        if (ctx->request_offset + block_size > piece_size)
                            block_size = piece_size - ctx->request_offset;

                        if (send_request(ctx, ctx->current_piece_idx, ctx->request_offset, block_size) == 1) {
                            ctx->request_offset += block_size;
                            ctx->pending_requests++;
                        } else break;
                    }
                }
            }

            if (ctx->state == PEER_STATE_DOWNLOADING && ctx->current_piece_idx >= 0) {
                long piece_size = meta->piece_length;
                if (ctx->current_piece_idx == meta->num_pieces - 1)
                    piece_size = meta->file_size - (ctx->current_piece_idx * meta->piece_length);

                if (ctx->piece_bytes_received >= piece_size && ctx->pending_requests == 0) {
                    if (verify_and_save_piece(ctx, state)) {
                        ctx->state = PEER_STATE_IDLE;
                    } else {
                        ctx->state = PEER_STATE_IDLE;
                    }
                }
            }
        }
    }

    printf("Download complete!\n");
    return 0;
}