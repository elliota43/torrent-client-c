//
// Created by Elliot Anderson on 12/28/25.
//

#include "bitfield.h"

int has_piece(unsigned char *bitfield, size_t bitfield_len, int piece_idx) {
    if (!bitfield) return 1; // if no bitfield received yet, assume they might have it

    int byte_index = piece_idx / 8;
    int bit_index = 7 - (piece_idx % 8); // high bit is piece 8

    if (byte_index >= bitfield_len) return 0; // out of bounds

    return (bitfield[byte_index] >> bit_index) & 1;
}