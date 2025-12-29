//
// Created by Elliot Anderson on 12/27/25.
//
#ifndef TORRENT_CLIENT_STATE_H
#define TORRENT_CLIENT_STATE_H

#pragma once
#include <pthread.h>
#include <stdint.h>
#include "tracker.h"

// File info for Multi-File Torrents
typedef struct {
    char *path;
    long length;
    long global_offset;
} FileInfo;

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
    int *piece_status; // 0=Todo, 1=In_Progress, 2=Done
    int pieces_done_count;
    long total_bytes_downloaded;

    pthread_mutex_t lock;
} SharedState;

// Helpers
void init_state(SharedState *state, TorrentMeta *meta, PeerInfo *peers, int count);
void free_state(SharedState *state);

#endif //TORRENT_CLIENT_STATE_H