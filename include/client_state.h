//
// Created by Elliot Anderson on 12/27/25.
//
#ifndef TORRENT_CLIENT_STATE_H
#define TORRENT_CLIENT_STATE_H

#pragma once
#include <pthread.h>
#include <stdint.h>
#include "tracker.h"
#include "connection_manager.h"

typedef enum {
    PEER_STATE_CONNECTING,
    PEER_STATE_HANDSHAKING,
    PEER_STATE_IDLE, // connected, waiting to ask for a piece
    PEER_STATE_DOWNLOADING, // currently pipelining requests
} ConnectionState;

// File info for Multi-File Torrents
typedef struct {
    char *path;
    long length;
    long global_offset;
} FileInfo;

typedef struct {
    int sock;
    int peer_idx; // index in the main 'peers' array
    ConnectionState state;

    // --- BUFFERS ---
    // need a buffer because recv() might give us half a message
    unsigned char recv_buff[16384];
    int recv_pos; // how many bytes currently in the buffer
    int msg_len_expected; // 0 if waiting for the 4-byte length prefix

    // ---- PROTOCL STATE -----
    int am_choked; // 1 if peer choked us
    int am_interested; // 1 if we told peer we are interested
    unsigned char *bitfield;
    size_t bitfield_len;

    // ---- DOWNLOAD JOB -----
    int current_piece_idx;
    long piece_position; // how many bytes of piece saved
    long request_offset; // how far ahead request is (pipelining)
    int pending_requests; // how many active requests
    char *temp_piece_buffer; // malloc'd buffer for piece being downloaded

    // Timeouts
    time_t last_activity;
} PeerContext;

// Read-only metadata about the torrent
typedef struct {
    long file_size;
    FileInfo *files;
    int num_files;
    long piece_length;
    long num_pieces;
    const char *pieces_concat;
    unsigned char info_hash[20];
    char *output_filename;
} TorrentMeta;

// Mutable state shared by threads
typedef struct {
    TorrentMeta *meta;
    PeerInfo *peers;
    int peer_count;

    PeerContext *connections;
    int max_connections;

    int *piece_status; // 0=Todo, 1=In_Progress, 2=Done
    int pieces_done_count;
    long total_bytes_downloaded;

    pthread_mutex_t lock;
} SharedState;

// Helpers
void init_state(SharedState *state, TorrentMeta *meta, PeerInfo *peers, int count);
void free_state(SharedState *state);

#endif //TORRENT_CLIENT_STATE_H