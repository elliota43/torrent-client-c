//
// Created by Elliot Anderson on 12/28/25.
//

#include "connection_manager.h"
#include "client_state.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>

void set_non_blocking_mode(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

void set_blocking_mode(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
}

// Initialize PeerContext from ConnectedPeer results
int init_peer_contexts(ConnectedPeer *connected, int count, void *contexts_ptr) {
    PeerContext *contexts = (PeerContext*)contexts_ptr;
    for (int i = 0; i < count; i++) {
        contexts[i].sock = connected[i].sock;
        contexts[i].peer_idx = connected[i].peer_idx;
        contexts[i].state = PEER_STATE_CONNECTING;
        contexts[i].recv_pos = 0;
        contexts[i].msg_len_expected = 0;
        contexts[i].am_choked = 1;
        contexts[i].am_interested = 0;
        contexts[i].bitfield = NULL;
        contexts[i].bitfield_len = 0;
        contexts[i].current_piece_idx = -1;
        contexts[i].piece_position = 0;
        contexts[i].request_offset = 0;
        contexts[i].pending_requests = 0;
        contexts[i].temp_piece_buffer = NULL;
        contexts[i].last_activity = time(NULL);
    }
    return count;
}

int scan_peers_async(PeerInfo *peers, int peer_count, ConnectedPeer *results, int max_results) {
    struct pollfd *pfds = malloc(peer_count *sizeof(struct pollfd));
    int *peer_indices = malloc(peer_count * sizeof(int));

    int active_sockets = 0;
    int successes = 0;

    printf("Async Scanner: Initiating %d connections...\n", peer_count);

    // Initiate Connections to everyone
    for (int i = 0; i < peer_count; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        set_non_blocking_mode(sock);

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = peers[i].port;
        addr.sin_addr.s_addr = peers[i].ip;

        int res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));

        if (res == 0) {
            // instant connection (rare)
            if (successes < max_results) {
                results[successes].sock = sock;
                results[successes].peer_idx = i;
                // Keep non-blocking for async downloader
                successes++;
            } else {
                close(sock);
            }
        }
        else if (res < 0 && errno == EINPROGRESS) {
            // connection happening in background
            pfds[active_sockets].fd = sock;
            pfds[active_sockets].events = POLLOUT; // wait for writable
            peer_indices[active_sockets] = i;
            active_sockets++;
        } else {
            // failed immediately
            close(sock);
        }
    }

    printf("Async Scanner: Waiting on %d sockets...\n", active_sockets);

    // Poll for Completion
    // give peers 3 seconds to connect
    int ret = poll(pfds, active_sockets, 5000);

    if (ret > 0) {
        for (int i = 0; i < active_sockets; i++) {
            if (successes >= max_results) {
                close(pfds[i].fd);
                continue;
            }

            // check if socket had activity
            if (pfds[i].revents & (POLLOUT | POLLERR | POLLHUP)) {
                int error = 0;
                socklen_t len = sizeof(error);
                getsockopt(pfds[i].fd, SOL_SOCKET, SO_ERROR, &error, &len);

                if (error == 0) {
                    // success - keep non-blocking for async downloader
                    results[successes].sock = pfds[i].fd;
                    results[successes].peer_idx = peer_indices[i];
                    successes++;
                } else {
                    close(pfds[i].fd);
                }
            } else {
                // no event happened (timeout)
                close(pfds[i].fd);
            }
        }
    } else {
        // total timeout, close everything
        for (int i = 0; i < active_sockets; i++) close(pfds[i].fd);
    }

    free(pfds);
    free(peer_indices);

    printf("Async Scanner: Connected to %d peers successfully.\n", successes);
    return successes;
}