//
// Created by Elliot Anderson on 12/27/25.
//

#ifndef TORRENT_CLIENT_PEER_H
#define TORRENT_CLIENT_PEER_H

#include <stdint.h>
#include "tracker.h"

int connect_to_peer(PeerInfo *peer, unsigned char *info_hash, char *my_peer_id);
int perform_handshake(int sock, unsigned char *info_hash, char *my_peer_id);

#endif //TORRENT_CLIENT_PEER_H