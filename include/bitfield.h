//
// Created by Elliot Anderson on 12/28/25.
//

#ifndef TORRENT_CLIENT_BITFIELD_H
#define TORRENT_CLIENT_BITFIELD_H

#pragma once
#include <stdint.h>
#include <stdlib.h>

// Helper to check a specific bit in a byte array
// Returns 1 if the peer has the piece, 0 if not
int has_piece(unsigned char *bitfield, size_t bitfield_len, int piece_idx);

#endif //TORRENT_CLIENT_BITFIELD_H