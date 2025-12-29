//
// Created by Elliot Anderson on 12/28/25.
//

#ifndef TORRENT_CLIENT_CONNECTION_MANAGER_H
#define TORRENT_CLIENT_CONNECTION_MANAGER_H

#pragma once
#include "tracker.h"

// Struct to hold successfully connected socket and identifying info
typedef struct {
    int sock;
    int peer_idx; // index in main peers array
} ConnectedPeer;

// Returns the number of successful connections
// Fills the 'results' array with connected sockets
int scan_peers_async(PeerInfo *peers, int peer_count, ConnectedPeer *results, int max_results);

#endif //TORRENT_CLIENT_CONNECTION_MANAGER_H