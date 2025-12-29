//
// Created by Elliot Anderson on 12/28/25.
//

#ifndef TORRENT_CLIENT_METADATA_H
#define TORRENT_CLIENT_METADATA_H

#include "tracker.h"

// Connects to a peer, performs extension handshake, and downloads the metadata.
// Returns a malloc'd buffer containing the raw info dict (bencoded), or NULL
char* fetch_metadata_from_peer(PeerInfo *peer, unsigned char *info_hash, char *my_id, long *out_len);

#endif //TORRENT_CLIENT_METADATA_H