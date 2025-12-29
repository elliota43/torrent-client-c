//
// Created by Elliot Anderson on 12/28/25.
//

#ifndef TORRENT_CLIENT_ASYNC_DOWNLOADER_H
#define TORRENT_CLIENT_ASYNC_DOWNLOADER_H

#pragma once
#include "client_state.h"

// Start the async download loop
// This replaces the worker thread model with a single event loop
int start_async_download(SharedState *state, char *my_id);

#endif //TORRENT_CLIENT_ASYNC_DOWNLOADER_H

