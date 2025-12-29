//
// Created by Elliot Anderson on 12/27/25.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include "peer.h"

int connect_to_peer(PeerInfo *peer, unsigned char *info_hash, char *my_peer_id) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // set up the address
    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = peer->port;
    peer_addr.sin_addr.s_addr = peer->ip;


    unsigned char *ip = (unsigned char *)&peer->ip;
    printf("Connecting to peer %d.%d.%d.%d:%d...\n",
        ip[0], ip[1], ip[2], ip[3], ntohs(peer->port));

    fflush(stdout); // force print before the potential wait

    // non-blocking
    // prevents connect() from hanging
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int res = connect(sock, (struct sockaddr *)&peer_addr, sizeof(peer_addr));

    if (res < 0) {
        if (errno == EINPROGRESS) {
            // connection is in background, we must wait
            fd_set set;
            FD_ZERO(&set);
            FD_SET(sock, &set);

            struct timeval timeout;
            timeout.tv_sec = 2;
            timeout.tv_usec = 0;

            res = select(sock + 1, NULL, &set, NULL, &timeout);

            if (res > 0) {
                // select says its ready, but check for errors
                int so_error;
                socklen_t len = sizeof(so_error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);

                if (so_error != 0) {
                    printf("Failed (Refused/Unreachable)\n");
                    close(sock);
                    return -1;
                }

                // If so_error = 0, connection succeeded!
            } else if (res == 0) {
                printf("Failed (Timeout)\n");
                close(sock);
                return -1;
            } else {
                perror("Select error");
                close(sock);
                return -1;
            }
        } else {
            perror("Connect error");
            close(sock);
            return -1;
        }
    }

    // restore blocking
    fcntl(sock, F_SETFL, flags);

    //


    // Send handshake
    char handshake[68];
    handshake[0] = 19;
    memcpy(handshake + 1, "BitTorrent protocol", 19);
    memset(handshake + 20, 0, 8); // Clear reserved bytes
    handshake[25] |= 0x10; // Set BEP 10 Extension Bit
    memcpy(handshake + 28, info_hash, 20);
    memcpy(handshake + 48, my_peer_id, 20);

    if (send(sock, handshake, 68, 0) != 68) {
        perror("Handshake send failed");
        close(sock);
        return -1;
    }

    struct timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Receive handshake
    char response[68];

    // wait for exactly 68 bytes
    ssize_t received = recv(sock, response, 68, MSG_WAITALL);

    if (received < 68) {
        printf("Peer closed connection or handshake invalid.\n");
        close(sock);
        return -1;
    }

    // Verify info hash
    if (memcmp(response + 28, info_hash, 20) != 0) {
        printf("Error: Peer has a different Info Hash!\n");
        close(sock);
        return -1;
    }

    printf("Connected to Peer! (Handshake Valid!)\n");
    return sock;

}

int perform_handshake(int sock, unsigned char *info_hash, char *my_peer_id) {
    // send handshake
    char handshake[68];
    handshake[0] = 19;
    memcpy(handshake + 1, "BitTorrent protocol", 19);
    memset(handshake + 20, 0, 8);
    handshake[25] |= 0x10;
    memcpy(handshake + 28, info_hash, 20);
    memcpy(handshake + 48, my_peer_id, 20);

    if (send(sock, handshake, 68, 0) != 68) {
        close(sock);
        return -1;
    }

    struct timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char response[68];
    ssize_t received = recv(sock, response, 68, MSG_WAITALL);

    if (received < 68) {
        close(sock);
        return -1;
    }

    if (memcmp(response + 28, info_hash, 20) != 0) {
        close(sock);
        return -1;
    }

    return 0; // Success
}