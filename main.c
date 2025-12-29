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
#include "bencode.h"
#include "tracker.h"
#include "peer.h"

#define BLOCK_SIZE 16384

#define NUM_THREADS 20

// ---------- Structs --------------

typedef struct {
    char *path;
    long length;
    long global_offset; // where this file starts in the torrent stream
} FileInfo;

typedef struct {
    long file_size; // total size (sum of all files)
    FileInfo *files; // array of files
    int num_files; // how many files
    long piece_length;
    long num_pieces;
    const char *pieces_concat; // raw pointer t the SHA1 hashes
    unsigned char info_hash[20];
    char *output_filename;
} TorrentMeta;

// Shared State for Threads
typedef struct {
    TorrentMeta *meta;
    PeerInfo *peers;
    int peer_count;
    int *piece_status; // 0=Todo, 1=In_Progress, 2=Done
    int pieces_done_count;
    pthread_mutex_t lock; // protect state
} SharedState;


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
            printf("ERROR: Could not map offset %ld to any file!\n", current_global_pos);
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

// Core Logic
int load_torrent_meta(char *filename, TorrentMeta *meta) {
    long torrent_len;
    char *data = read_file(filename, &torrent_len);
    if (!data) return 0;

    TorrentVal *torrent_data = NULL;
    parse_bencoded_dict(data, &torrent_data);

    TorrentVal *info = find_key(torrent_data, "info");
    if (!info) { printf("Error: no info dict.\n"); return 0; }

    // Calculate Info Hash
    long info_len = info->end - info->start;
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, (unsigned char*)info->start, info_len);
    SHA1_Final(meta->info_hash, &ctx);

    // Check if multi-file
    TorrentVal *files_list = find_key(info->val.l, "files");

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

        printf("Mode: Multi-File (%d files)\n", meta->num_files);
    } else {
        // --- Single File Mode ----
        meta->num_files = 1;
        meta->files = malloc(sizeof(FileInfo));

        TorrentVal *t_len = find_key(info->val.l, "length");
        TorrentVal *t_name = find_key(info->val.l, "name");

        meta->files[0].length = t_len->val.i;
        meta->files[0].global_offset = 0;
        meta->files[0].path = strdup(t_name->val.s);

        meta->file_size = t_len->val.i;
        printf("Mode: Single-File\n");
    }

    // Get Piece Info
    TorrentVal *t_piece_len = find_key(info->val.l, "piece length");
    TorrentVal *t_pieces = find_key(info->val.l, "pieces");

    if (!meta->file_size || !t_piece_len || !t_pieces) return 0;

    meta->piece_length = t_piece_len->val.i;
    meta->num_pieces = (meta->file_size + meta->piece_length - 1) / meta->piece_length;
    meta->output_filename = "sintel_final.mp4";

    // Pointer arithmetic for Raw Hashes
    char *raw_ptr = t_pieces->start;
    while (isdigit(*raw_ptr)) raw_ptr++;
    if (*raw_ptr == ':') raw_ptr++;
    meta->pieces_concat = raw_ptr;

    // todo: free bencode tree
    return 1;
}

int attempt_download_piece(int piece_idx, PeerInfo *peer, TorrentMeta *meta, char *my_id) {
    int sock = connect_to_peer(peer, meta->info_hash, my_id);
    if (sock == -1) return 0;

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
    const int MAX_PIPELINE = 10; // keep 10 reqs active at all times
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
            printf("\n Piece %d verified!\n", piece_idx);

            long global_offset = piece_idx * meta->piece_length;
            write_block_to_files(meta, global_offset, piece_data, piece_size);

            success = 1;
        } else {
            printf("\n Hash failure for piece %d\n", piece_idx);
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

        // try downloading
        // simple random peer selection
        // @todo: consider looking for rare pieces first
        int attempts = 0;
        int success = 0;
        while (!success && attempts < 5) { // try 5 peers before giving up on piece
            int peer_idx = rand() % state->peer_count;
            if (state->peers[peer_idx].ip == 0) { attempts++; continue; }

            // Log output needs lock to not be messy
            pthread_mutex_lock(&state->lock);
            printf("Thread %p: Downloading Piece %d/%ld from Peer %d\n",
                (void*)pthread_self(), piece_index, state->meta->num_pieces, peer_idx);
            pthread_mutex_unlock(&state->lock);

            success = attempt_download_piece(piece_index, &state->peers[peer_idx], state->meta, my_id);
            if (!success) attempts++;
        }

        // Report Result
        pthread_mutex_lock(&state->lock);
        if (success) {
            state->piece_status[piece_index] = 2; // 2 = Done
            state->pieces_done_count++;
            printf(">>> Piece %d COMPLETE. (%d/%ld)\n", piece_index, state->pieces_done_count, state->meta->num_pieces);
        } else {
            state->piece_status[piece_index] = 0; // reset to 0 (todo)
            printf("!!! Piece %d FAILED. Resetting.\n", piece_index);
        }
        pthread_mutex_unlock(&state->lock);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2 ) {
        printf("Usage: %s <file.torrent>\n", argv[0]);
        return 1;
    }

    srand(time(NULL));

    // Setup
    TorrentMeta meta;
    printf("Loading Torrent Metadata...\n");
    if (!load_torrent_meta(argv[1], &meta)) return 1;

    printf("Total Size:   %ld bytes\n", meta.file_size);
    printf("Piece Length: %ld bytes\n", meta.piece_length);
    printf("Total Blocks: %ld\n", meta.num_pieces);

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
    printf("Found %d peers. Starting %d threads...\n\n", peer_count, NUM_THREADS);

    // Initialize Shared State
    SharedState state;
    state.meta = &meta;
    state.peers = peers;
    state.peer_count = peer_count;
    state.piece_status = calloc(meta.num_pieces, sizeof(int));
    state.pieces_done_count = 0;
    pthread_mutex_init(&state.lock, NULL);

    // spawn threads
    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &state);
    }

    // Wait for Join
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\nDownload Complete!\n");
    free(state.piece_status);
    free(peers);
    pthread_mutex_destroy(&state.lock);


    return 0;

}