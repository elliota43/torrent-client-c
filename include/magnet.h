//
// Created by Elliot Anderson on 12/28/25.
//

#ifndef TORRENT_CLIENT_MAGNET_H
#define TORRENT_CLIENT_MAGNET_H

#pragma once
#include "client_state.h"

// Parses a magnet link and extracts the 20-byte info hash
// returns 1 on success, 0 on failure
int parse_magnet_uri(const char *uri, TorrentMeta *meta);

#endif //TORRENT_CLIENT_MAGNET_H