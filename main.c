
#include "bencode.h"
#include "tracker.h"
#include "peer.h"
#include "client_state.h"
#include "bitfield.h"
#include "magnet.h"
#include "metadata.h"
#include "connection_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <sys/time.h>

#define BLOCK_SIZE 16384

#define NUM_THREADS 20
#define MAX_PIPELINE 10

// ANSI Colors
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1bp[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_RESET "\x1b[0m"


// ------- Helper Functions --------

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

// Helper to ensure directories exist
// for now, this jsut opens file in r+b (update) or w+b (create)
void write_block_to_files(TorrentMeta *meta, long global_offset, char *data, long data_len) {
    long bytes_written = 0;

    while (bytes_written < data_len) {
        long current_global_pos = global_offset + bytes_written;
        long bytes_left_to_write = data_len - bytes_written;

        // Find which file covers the current global position
        FileInfo *target_file = NULL;
        for (int i = 0; i < meta->num_files; i++) {
            long f_start = meta->files[i].global_offset;
            long f_end = f_start + meta->files[i].length;

            if (current_global_pos >= f_start && current_global_pos < f_end) {
                target_file = &meta->files[i];
                break;
            }
        }

        if (!target_file) {
            break;
        }

        // Calculate offset within the specific file
        long file_relative_offset = current_global_pos - target_file->global_offset;

        // how much can we write to file before hitting the end
        long space_in_file = target_file->length - file_relative_offset;
        long chunk_size = (bytes_left_to_write < space_in_file) ? bytes_left_to_write : space_in_file;

        // write data
        FILE *f = fopen(target_file->path, "r+b"); // try opening for update
        if (!f) {
            f = fopen(target_file->path, "wb"); // create if it doesnt exist
            // @todo: pre-allocate all files with empty zeros
        }
        if (!f) { perror("File open error"); return; }

        fseek(f, file_relative_offset, SEEK_SET);
        fwrite(data + bytes_written, 1, chunk_size, f);
        fclose(f);

        bytes_written += chunk_size;
    }
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

int attempt_download_piece(int piece_idx, PeerInfo *peer, TorrentMeta *meta, char *my_id, SharedState *state, int pre_connected_sock) {

    // bitfield check (skip if they dont have it)
    if (peer->bitfield && !has_piece(peer->bitfield, peer->bitfield_len, piece_idx)) {
        return 0; // skip, peer doesnt have the piece
    }

    int sock;

    // socket setup
    if (pre_connected_sock != -1) {
        // use async socket provided by worker_thread
        // note: handshake already performed in worker_thread
        sock = pre_connected_sock;
    } else {
        // fallback: create new connection (standard blocking)
        sock = connect_to_peer(peer, meta->info_hash, my_id);
        if (sock == -1) return 0;
    }

    // Set Timeout (2s)
    struct timeval timeout = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    unsigned char interested[] = {0, 0, 0, 1, 2};
    send(sock, interested, 5, 0);

    // Calculate exact piece size
    long piece_size = meta->piece_length;
    if (piece_idx == meta->num_pieces - 1) {
        piece_size = meta->file_size - (piece_idx * meta->piece_length);
    }

    char *piece_data = malloc(piece_size);
    if (!piece_data) { close(sock); return 0; }

    // Pipelining
    int is_choked = 1;
    long bytes_recvd = 0; // already saved
    long requested_offset = 0; // already asked for
    int pending_requests = 0; // active requests
    int success = 0;

    while (bytes_recvd < piece_size) {
        // fill the pipe
        // if unchoked and haven't filled pipeline queue, send more requests
        while (!is_choked && pending_requests < MAX_PIPELINE && requested_offset < piece_size) {

            long block_size = BLOCK_SIZE;
            if (requested_offset + block_size > piece_size) {
                block_size = piece_size - requested_offset;
            }

            // Construct Request Packet
            uint32_t req_len = htonl(13);
            uint8_t req_id = 6;
            uint32_t idx = htonl(piece_idx);
            uint32_t begin = htonl(requested_offset);
            uint32_t len = htonl(block_size);

            unsigned char req[17];
            memcpy(req, &req_len, 4);
            memcpy(req + 4, &req_id, 1);
            memcpy(req + 5, &idx, 4);
            memcpy(req + 9, &begin, 4);
            memcpy(req + 13, &len, 4);

            if (send(sock, req, 17, 0) < 0) {
                // if send fails, stop loop
                break;
            }

            requested_offset += block_size;
            pending_requests++;
        }

        // Receive Data
        // must receive data even if choked to process control messages
        uint32_t msg_len_net;
        if (recv_exact(sock, &msg_len_net, 4) != 0) break;
        uint32_t msg_len = ntohl(msg_len_net);

        if (msg_len == 0) continue; // keep-alive

        uint8_t msg_id;
        if (recv_exact(sock, &msg_id, 1) != 0) break;
        uint32_t payload_len = msg_len - 1;

        if (msg_id == 5) { // BITFIELD MESSAGE
            if (peer->bitfield) free(peer->bitfield);
            peer->bitfield = malloc(payload_len);
            peer->bitfield_len = payload_len;
            if (recv_exact(sock, peer->bitfield, payload_len) != 0) break;

            // we have bitfield map, does the peer have the piece we want
            if (!has_piece(peer->bitfield, payload_len, piece_idx)) {
                break; // bail
            }
            continue;
        }

        if (msg_id == 0) {
            is_choked = 1;
        } else if (msg_id == 1) {
            is_choked = 0; // unchoked
        } else if (msg_id == 7) { // piece
            char header[8];
            if (recv_exact(sock, header, 8) != 0) break;

            uint32_t recv_offset = ntohl(*(uint32_t*)&header[4]);
            uint32_t data_size = payload_len - 8;

            // Read data directly into correct spot in the buffer
            // use recv_offset because piped requests may arrive out of order
            if (recv_offset + data_size > piece_size) break;

            if (recv_exact(sock, piece_data + recv_offset, data_size) != 0) break;

            bytes_recvd += data_size;
            pending_requests--; // create more room in pipeline for another request

            pthread_mutex_lock(&state->lock);
            state->total_bytes_downloaded += data_size;
            pthread_mutex_unlock(&state->lock);

            // progress bar
            if (bytes_recvd % (BLOCK_SIZE * 4) == 0) { printf("."); fflush(stdout); }
        } else {
            // skip other messages
            char *trash = malloc(payload_len);
            recv_exact(sock, trash, payload_len);
            free(trash);
        }
    }

    // Verify & write
    if (bytes_recvd >= piece_size) {
        const unsigned char *expected = (const unsigned char*)(meta->pieces_concat + piece_idx * 20);
        if (verify_piece_hash((unsigned char*)piece_data, piece_size, expected)) {
            long global_offset = piece_idx * meta->piece_length;
            write_block_to_files(meta, global_offset, piece_data, piece_size);
            success = 1;
        }
    }

    free(piece_data);
    close(sock);
    return success;
}

// Worker Thread
void* worker_thread(void *arg) {
    SharedState *state = (SharedState*)arg;
    char my_id[21];
    sprintf(my_id, "-TC0001-%012d", rand());

    while (1) {
        int piece_index = -1;

        // Find a job
        pthread_mutex_lock(&state->lock);
        if (state->pieces_done_count >= state->meta->num_pieces) {
            pthread_mutex_unlock(&state->lock);
            break;
        }

        for (int i = 0; i < state->meta->num_pieces; i++) {
            if (state->piece_status[i] == 0) { // todo
                piece_index = i;
                state->piece_status[i] = 1; // in progress
                break;
            }
        }
        pthread_mutex_unlock(&state->lock);

        if (piece_index == -1) {
            // no jobs currently available, but download isn't finished.
            sleep(1);
            continue;
        }

        // Get a connected socket

        int sock = -1;
        int peer_idx = -1;

        pthread_mutex_lock(&state->lock);
        if (state->active_conn_ptr < state->active_conn_count) {
            sock = state->active_connections[state->active_conn_ptr].sock;
            peer_idx = state->active_connections[state->active_conn_ptr].peer_idx;
            state->active_conn_ptr++;
        }
        pthread_mutex_unlock(&state->lock);

        // if  out of pre-connected sockets, just sleep for now

        if (sock == -1) {
            // reset piece status so someone else can try later
            pthread_mutex_lock(&state->lock);
            state->piece_status[piece_index] = 0;
            pthread_mutex_unlock(&state->lock);
            sleep(1);
            continue;
        }

        // handshake && download
        if (perform_handshake(sock, state->meta->info_hash, my_id) == 0) {

            // pass the ready socket to the download function
            int success = attempt_download_piece(piece_index, &state->peers[peer_idx], state->meta, my_id, state, sock);

            pthread_mutex_lock(&state->lock);
            if (success) {
                state->piece_status[piece_index] = 2; // done
                state->pieces_done_count++;
            } else {
                state->piece_status[piece_index] = 0; // retry later
            }
            pthread_mutex_unlock(&state->lock);
        } else {
            // handshake failed.  socket closed inside perform_handshake
            // reset piece to todo
            pthread_mutex_lock(&state->lock);
            state->piece_status[piece_index] = 0;
            pthread_mutex_unlock(&state->lock);
        }
    }
    return NULL;
}

// Monitor Thread for Visuals
void* monitor_thread(void *arg) {
    SharedState *state = (SharedState*)arg;
    long prev_bytes = 0;

    printf("\033[2J"); // Clear Screen

    while (1) {
        pthread_mutex_lock(&state->lock);
        int done = state->pieces_done_count;
        int total = state->meta->num_pieces;
        long bytes = state->total_bytes_downloaded;
        int is_complete = (done >= total);
        pthread_mutex_unlock(&state->lock);

        // Speed Calc
        double speed_mbps = (double)(bytes - prev_bytes) / 1024.0 / 1024.0 * 5.0; // *5 because we sleep 200ms
        prev_bytes = bytes;

        // Progress Bar
        float percent = (float)done / total * 100.0;
        int bar_width = 40;
        int pos = bar_width * percent / 100;

        printf("\033[H"); // Move cursor to top left
        printf("\n " ANSI_COLOR_BLUE "BITTORRENT CLIENT v1.0" ANSI_COLOR_RESET "\n");
        printf(" ----------------------------------------\n");
        printf(" File: %s\n", state->meta->output_filename ? state->meta->output_filename : "Multi-File");
        printf(" Size: %.2f MB\n", (double)state->meta->file_size / 1024 / 1024);
        printf(" Peers: %d | Threads: %d\n", state->peer_count, NUM_THREADS);
        printf(" ----------------------------------------\n");

        printf(" Progress: [");
        for (int i = 0; i < bar_width; ++i) {
            if (i < pos) printf(ANSI_COLOR_GREEN "=" ANSI_COLOR_RESET);
            else if (i == pos) printf(ANSI_COLOR_GREEN ">" ANSI_COLOR_RESET);
            else printf(" ");
        }
        printf("] " ANSI_COLOR_YELLOW "%.2f%%" ANSI_COLOR_RESET "\n", percent);
        printf(" Pieces:   %d / %d\n", done, total);
        printf(" Speed:    " ANSI_COLOR_RED "%.2f MB/s" ANSI_COLOR_RESET "\n", speed_mbps);

        fflush(stdout); // force terminal to draw immediately

        if (is_complete) break;
        usleep(200000);
    }
    return NULL;
}

// Process metadata already loaded into memory (either from file or network)
int process_metadata_buffer(char *data, long data_len, TorrentMeta *meta) {
    TorrentVal *torrent_data = NULL;
    parse_bencoded_dict(data, &torrent_data);

    // if from file, 'info' is a key.  if its from extension protocol, it IS the info dict.
    TorrentVal *metadata_root = NULL;
    TorrentVal *info_key = find_key(torrent_data, "info");

    if (info_key) {
        // .torrent file (Metadata inside "info" key)
        metadata_root = info_key->val.l;

        // calculate info hash if missing
        unsigned char empty[20] = {0};
        if (memcmp(meta->info_hash, empty, 20) == 0) {
            long info_len = info_key->end - info_key->start;
            SHA_CTX ctx;
            SHA1_Init(&ctx);
            SHA1_Update(&ctx, (unsigned char*)info_key->start, info_len);
            SHA1_Final(meta->info_hash, &ctx);
        }
    } else {
        metadata_root = torrent_data;
    }

    if (!metadata_root) return 0;


    // Parse file/multi-file info
    TorrentVal *files_list = find_key(metadata_root, "files");
    if (files_list) {
        // ----- MULTI FILE ----

        int count = 0;
        TorrentVal *curr = files_list->val.l;
        while (curr) { count++; curr = curr->next; }

        // allocate memory for the file list
        meta->files = malloc(count * sizeof(FileInfo));
        meta->num_files = count;
        meta->file_size = 0;

        // loop through and populate struct
        curr = files_list->val.l;
        int i = 0;
        while (curr) {
            TorrentVal *f_len = find_key(curr->val.l, "length");
            TorrentVal *f_path_list = find_key(curr->val.l, "path");

            meta->files[i].length = f_len->val.i;
            meta->files[i].global_offset = meta->file_size; // starts where previous file ended

            // flatten path list: ["sintel", "poster.jpg"] -> "sintel_poster.jpg"
            char filename_buf[1024] = {0};
            TorrentVal *p_seg = f_path_list->val.l;
            while (p_seg) {
                strcat(filename_buf, p_seg->val.s);
                if (p_seg->next) strcat(filename_buf, "_"); // add separator
                p_seg = p_seg->next;
            }

            meta->files[i].path = strdup(filename_buf);

            // update total size
            meta->file_size += meta->files[i].length;

            i++;
            curr = curr->next;
        }
    } else {
        // --- Single File Mode ----
        meta->num_files = 1;
        meta->files = malloc(sizeof(FileInfo));

        TorrentVal *t_len = find_key(metadata_root, "length");
        TorrentVal *t_name = find_key(metadata_root, "name");

        if (!t_len || !t_name) {
            printf("Error: Missing length or name in single-file torrent.\n");
            return 0;
        }

        meta->files[0].length = t_len->val.i;
        meta->files[0].global_offset = 0;
        meta->files[0].path = strdup(t_name->val.s);

        meta->file_size = t_len->val.i;
        printf("Mode: Single-File\n");
    }

    // Piece Length
    TorrentVal *t_piece_len = find_key(metadata_root, "piece length");
    TorrentVal *t_pieces = find_key(metadata_root, "pieces");
    if (!t_piece_len || !t_pieces) return 0;

    meta->piece_length = t_piece_len->val.i;
    meta->num_pieces = (meta->file_size + meta->piece_length - 1) / meta->piece_length;

    // Pieces string
    const char *raw_ptr = t_pieces->start;
    while (isdigit(*raw_ptr)) raw_ptr++;
    if (*raw_ptr == ':') raw_ptr++;
    meta->pieces_concat = raw_ptr;

    return 1;
}

// Wrapper for Files
int load_torrent_file(char *filename, TorrentMeta *meta) {
    long len;
    char *data = read_file(filename, &len);
    if (!data) return 0;
    return process_metadata_buffer(data, len, meta);
}

int main(int argc, char *argv[]) {
    if (argc != 2 ) {
        printf("Usage: %s <file.torrent>\n", argv[0]);
        return 1;
    }

    srand(time(NULL));

    // Setup
    TorrentMeta meta;
    memset(&meta, 0, sizeof(TorrentMeta)); // clear memory

    int is_magnet = (strncmp(argv[1], "magnet:", 7) == 0);
    char my_id[21];
    sprintf(my_id, "-TC001-%012d", rand());

    // initialization
    if (is_magnet) {
        printf("Magnet Link Detected. Parsing Hash...\n");
        if (!parse_magnet_uri(argv[1], meta.info_hash)) {
            printf("Invalid Magnet Link.\n");
            return 1;
        }
    } else {
        printf("Loading Torrent File...\n");
        if (!load_torrent_file(argv[1], &meta)) return 1;
    }


    // Tracker
    printf("Connecting to Tracker...\n");
    TrackerUrl *t_url = parse_tracker_url("udp://tracker.opentrackr.org:1337");
    struct sockaddr_in tracker_addr;
    get_tracker_addr(t_url, &tracker_addr);

    int sock = -1;
    int64_t conn_id = udp_announce_connect(&tracker_addr, &sock);
    if (conn_id == -1) { printf("Tracker Handshake failed.\n"); return 1; }

    PeerInfo *peers = NULL;
    int peer_count = udp_announce_request(sock, &tracker_addr, conn_id, meta.info_hash, &peers);
    close(sock);

    if (peer_count <= 0) { printf("No Peers found.\n"); return 1; }
    printf("Found %d peers. \n", peer_count);

    // Magnet Metadata
    if (is_magnet) {
        printf("Magnet File: Hunting for Metadata...\n");

        char *info_buf = NULL;
        long info_len = 0;

        for (int i = 0; i < peer_count; i++) {
            printf("Asking Peer %d...\n", i);

            info_buf = fetch_metadata_from_peer(&peers[i], meta.info_hash, my_id, &info_len);
            if (info_buf) break;
        }

        if (!info_buf) {
            printf("Critical: Could not fetch metadata from any peer. Aborting.\n");
            return 1;
        }

        // Parse metadata buffer we just downloaded
        if (!process_metadata_buffer(info_buf, info_len, &meta)) {
            printf("Critical: Invalid metadata received.\n");
            return 1;
        }
    }

    int max_conns = 50; // or peer_count??
    ConnectedPeer *active_conns = malloc(max_conns * sizeof(ConnectedPeer));
    int num_active = scan_peers_async(peers, peer_count, active_conns, max_conns);

    if (num_active == 0) {
        printf("Async Scan failed to connect to any peers.\n");
        return 1;
    }

    // Start Download

    printf("Metadata Loaded. Starting Download...\n");
    printf("Total Size:   %ld bytes\n", meta.file_size);
    printf("Piece Length: %ld bytes\n", meta.piece_length);
    printf("Total Blocks: %ld\n", meta.num_pieces);

    // Initialize Shared State
    SharedState state;
    state.meta = &meta;
    state.peers = peers;
    state.peer_count = peer_count;

    state.active_connections = active_conns;
    state.active_conn_count = num_active;
    state.active_conn_ptr = 0;

    state.piece_status = calloc(meta.num_pieces, sizeof(int));
    state.pieces_done_count = 0;
    state.total_bytes_downloaded = 0;
    pthread_mutex_init(&state.lock, NULL);

    // spawn threads
    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &state);
    }

    // Spawn Monitor
    pthread_t monitor;
    pthread_create(&monitor, NULL, monitor_thread, &state);

    // Wait for Join
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\n" ANSI_COLOR_GREEN "Download Complete!" ANSI_COLOR_RESET "\n");
    free(state.piece_status);
    free(peers);
    pthread_mutex_destroy(&state.lock);
    return 0;
}