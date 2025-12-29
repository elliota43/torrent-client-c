//
// Created by Elliot Anderson on 12/29/25.
//

#include "client_state.h"
#include "peer.h"
#include "connection_manager.h"
#include <sys/socket.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#define MAX_CONNS 50

void process_message(PeerContext *p, SharedState *state);

// Initialize the Pool
void init_peer_pool(SharedState *state) {
    state->max_connections = MAX_CONNS;
    state->connections =  calloc(MAX_CONNS, sizeof(PeerContext));
    for (int i = 0; i < MAX_CONNS; i++) {
        state->connections[i].sock = -1; // -1 means slot is empty
    }
}

// Add new connection to pool
void add_connection(SharedState *state, int sock, int peer_idx) {
    for (int i = 0; i < state->max_connections; i++) {
        if (state->connections[i].sock == -1) {
            // Found empty slot
            memset(&state->connections[i], 0, sizeof(PeerContext));
            state->connections[i].sock = sock;
            state->connections[i].peer_idx = peer_idx;
            state->connections[i].state = PEER_STATE_HANDSHAKING; // next step is handshake
            state->connections[i].am_choked = 1;
            state->connections[i].last_activity = time(NULL);

            // set non-blocking just in case
            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);

            // send handshake
            perform_handshake_send(sock, state->meta->info_hash, "-TC0001-...");

            printf("Slot %d: Peer Connected. Sent Handshake.\n", i);
            return;
        }
    }
    // pool full? close it
    close(sock);
}

// Main Loop
void run_async_loop(SharedState *state) {
    struct pollfd pfds[MAX_CONNS];

    while (state->pieces_done_count < state->meta->num_pieces) {
        int active_count = 0;

        //Prepare Poll List
        for (int i = 0; i < state->max_connections; i++) {
            if (state->connections[i].sock != -1) {
                pfds[active_count].fd = state->connections[i].sock;
                pfds[active_count].events = POLLIN; // alert when data arrives

                active_count++;
            }
        }

        if (active_count == 0) {
            // scan for more peers if empty @todo
            sleep(1);
            continue;
        }

        // poll (wait 100ms)
        int ret = poll(pfds, active_count, 100);

        if (ret > 0) {
            int current_pfd = 0;
            for (int i = 0; i < state->max_connections; i++) {
                if (state->connections[i].sock == -1) continue;

                // check if socket woke up
                if (pfds[current_pfd].revents & POLLIN) {
                    PeerContext *p = &state->connections[i];

                    // read into buffer at current position
                    int space_left = sizeof(p->recv_buf) - p->recv_pos;
                    ssize_t r = recv(p->sock, p->recv_buf + p->recv_pos, space_left, 0);

                    if (r <= 0) {
                        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            // Spurious wakeup, ignore
                        } else {
                            // Disconnect / Error
                            close(p->sock);
                            p->sock = -1; // Mark slot free
                            // Handle cleanup (reset piece status if downloading)
                        }
                    } else {
                        p->recv_pos += r;
                        p->last_activity = time(NULL);
                        process_message(p, state); // Parse buffer
                    }
                }
                current_pfd++;
            }
        }

        // Period Tasks (Pipelining, Timeouts) @todo
        // loop through connections, fill pipeline if unchoked, check for timeouts.
    }
}