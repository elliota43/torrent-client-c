//
// Created by Elliot Anderson on 12/29/25.
//

#ifndef TORRENT_CLIENT_SEEDER_H
#define TORRENT_CLIENT_SEEDER_H

#pragma once
#include "client_state.h"

// Handles an incoming REQUEST (ID 6) message.
// Reads data from disk and sends a PIECE (ID 7) message back
void handle_peer_request(PeerContext *ctx, SharedState *state, uint32_t piece_idx, uint32_t begin, uint32_t len);

// Broadcasts a HAVE (ID 4) message to all connected peers
// Call this immediately after successfully verifying a download piece.
void broadcast_have(SharedState *state, int piece_idx);

#endif //TORRENT_CLIENT_SEEDER_H