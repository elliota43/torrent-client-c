//
// Created by Elliot Anderson on 12/27/25.
//
#pragma once

#include <netinet/in.h>

#ifndef TORRENT_CLIENT_STATE_H
#define TORRENT_CLIENT_STATE_H

typedef struct {
    // Configuration
    int port;
    char peer_id[20];

    // Status
    int pieces_downloaded;
    int pieces_total;
    int is_choked;

    // Networking
    int socket_fd;
    struct sockaddr_in tracker_addr;
} TorrentClientState;

#endif //TORRENT_CLIENT_STATE_H