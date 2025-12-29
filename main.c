#include "bencode.h"
#include "tracker.h"
#include "peer.h"
#include "client_state.h"
#include "bitfield.h"
#include "magnet.h"
#include "metadata.h"
#include "connection_manager.h"
#include "async_downloader.h"

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

#define NUM_THREADS 20

// ANSI Colors
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1bp[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_RESET "\x1b[0m"


// ------- Helper Functions --------

char* read_file(const char* filename, long* out_len) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *out_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(*out_len + 1);
    fread(buf, 1, *out_len, f);
    fclose(f);
    buf[*out_len] = '\0';
    return buf;
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
        
        // Count active connections (optional visual improvement)
        int active = 0;
        for(int i=0; i<state->max_connections; i++) {
            if(state->connections[i].sock > 0) active++;
        }
        pthread_mutex_unlock(&state->lock);

        // Speed Calc
        double speed_mbps = (double)(bytes - prev_bytes) / 1024.0 / 1024.0 * 5.0; 
        prev_bytes = bytes;

        // Progress Bar
        float percent = (float)done / total * 100.0;
        int bar_width = 40;
        int pos = bar_width * percent / 100;

        printf("\033[H"); 
        printf("\n " ANSI_COLOR_BLUE "BITTORRENT CLIENT v2.0 (Async)" ANSI_COLOR_RESET "\n");
        printf(" ----------------------------------------\n");
        printf(" File: %s\n", state->meta->output_filename ? state->meta->output_filename : "Multi-File");
        printf(" Size: %.2f MB\n", (double)state->meta->file_size / 1024 / 1024);
        printf(" Active Peers: %d / %d\n", active, state->peer_count);
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

        fflush(stdout); 

        if (is_complete) break;
        usleep(200000);
    }
    return NULL;
}

TorrentVal* find_key(TorrentVal *dict, const char *key) {
    TorrentVal *curr = dict;
    while (curr) {
        if (curr->key && strcmp(curr->key, key) == 0) return curr;
        curr = curr->next;
    }
    return NULL;
}
// Process metadata buffer (reused from your code)
int process_metadata_buffer(char *data, long data_len, TorrentMeta *meta) {
    TorrentVal *torrent_data = NULL;
    parse_bencoded_dict(data, &torrent_data);

    TorrentVal *metadata_root = NULL;
    TorrentVal *info_key = find_key(torrent_data, "info");

    if (info_key) {
        metadata_root = info_key->val.l;
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

    TorrentVal *files_list = find_key(metadata_root, "files");
    if (files_list) {
        int count = 0;
        TorrentVal *curr = files_list->val.l;
        while (curr) { count++; curr = curr->next; }

        meta->files = malloc(count * sizeof(FileInfo));
        meta->num_files = count;
        meta->file_size = 0;

        curr = files_list->val.l;
        int i = 0;
        while (curr) {
            TorrentVal *f_len = find_key(curr->val.l, "length");
            TorrentVal *f_path_list = find_key(curr->val.l, "path");

            meta->files[i].length = f_len->val.i;
            meta->files[i].global_offset = meta->file_size;

            char filename_buf[1024] = {0};
            TorrentVal *p_seg = f_path_list->val.l;
            while (p_seg) {
                strcat(filename_buf, p_seg->val.s);
                if (p_seg->next) strcat(filename_buf, "_");
                p_seg = p_seg->next;
            }
            meta->files[i].path = strdup(filename_buf);
            meta->file_size += meta->files[i].length;
            i++;
            curr = curr->next;
        }
    } else {
        meta->num_files = 1;
        meta->files = malloc(sizeof(FileInfo));
        TorrentVal *t_len = find_key(metadata_root, "length");
        TorrentVal *t_name = find_key(metadata_root, "name");
        
        if (t_len && t_name) {
            meta->files[0].length = t_len->val.i;
            meta->files[0].global_offset = 0;
            meta->files[0].path = strdup(t_name->val.s);
            meta->file_size = t_len->val.i;
        }
    }

    TorrentVal *t_piece_len = find_key(metadata_root, "piece length");
    TorrentVal *t_pieces = find_key(metadata_root, "pieces");
    if (!t_piece_len || !t_pieces) return 0;

    meta->piece_length = t_piece_len->val.i;
    meta->num_pieces = (meta->file_size + meta->piece_length - 1) / meta->piece_length;

    const char *raw_ptr = t_pieces->start;
    while (isdigit(*raw_ptr)) raw_ptr++;
    if (*raw_ptr == ':') raw_ptr++;
    meta->pieces_concat = raw_ptr;

    return 1;
}

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
    memset(&meta, 0, sizeof(TorrentMeta)); 

    int is_magnet = (strncmp(argv[1], "magnet:", 7) == 0);
    char my_id[21];
    sprintf(my_id, "-TC001-%012d", rand());

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

        if (!process_metadata_buffer(info_buf, info_len, &meta)) {
            printf("Critical: Invalid metadata received.\n");
            return 1;
        }
    }

    // --- ASYNC SCANNER ---
    int max_conns = 50;
    ConnectedPeer *active_conns = malloc(max_conns * sizeof(ConnectedPeer));
    int num_active = scan_peers_async(peers, peer_count, active_conns, max_conns);

    if (num_active == 0) {
        printf("Async Scan failed to connect to any peers.\n");
    }

    // --- SETUP DOWNLOAD ---
    printf("Metadata Loaded. Starting Download...\n");
    printf("Total Size:   %ld bytes\n", meta.file_size);
    printf("Piece Length: %ld bytes\n", meta.piece_length);
    printf("Total Pieces: %ld\n", meta.num_pieces);

    SharedState state;
    state.meta = &meta;
    state.peers = peers;
    state.peer_count = peer_count;

    // Allocate connection pool
    state.connections = calloc(max_conns, sizeof(PeerContext));
    state.max_connections = max_conns;
    
    // Initialize pool with the already connected sockets
    init_peer_contexts(active_conns, num_active, state.connections);

    state.piece_status = calloc(meta.num_pieces, sizeof(int));
    state.pieces_done_count = 0;
    state.total_bytes_downloaded = 0;
    pthread_mutex_init(&state.lock, NULL);

    // Spawn Monitor Thread (Maintains Visuals)
    pthread_t monitor;
    pthread_create(&monitor, NULL, monitor_thread, &state);

    // *** START MAIN EVENT LOOP ***
    // This blocks until download completes or fails
    start_async_download(&state, my_id);

    // Cleanup
    pthread_join(monitor, NULL);
    for (int i = 0; i < max_conns; i++) {
        if (state.connections[i].sock > 0) close(state.connections[i].sock);
        if (state.connections[i].bitfield) free(state.connections[i].bitfield);
        if (state.connections[i].temp_piece_buffer) free(state.connections[i].temp_piece_buffer);
    }

    printf("\n" ANSI_COLOR_GREEN "Download Complete!" ANSI_COLOR_RESET "\n");
    free(state.connections);
    free(state.piece_status);
    free(active_conns);
    free(peers);
    pthread_mutex_destroy(&state.lock);
    return 0;
}