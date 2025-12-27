//
// Created by Elliot Anderson on 12/27/25.
//

#pragma once

#include "tracker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

TrackerUrl* parse_tracker_url(const char *url) {
    TrackerUrl *t = malloc(sizeof(TrackerUrl));
    t->host = NULL;
    t->path = NULL;
    t->port = 80;
    t->protocol = TRACKER_HTTP; // default to HTTP for now

    // detect protocol
    const char *p = url;
    if (strncmp(url, "udp://", 6) == 0) {
        t->protocol = TRACKER_UDP;
        p += 6;
    } else if (strncmp(url, "http://", 7) == 0) {
        t->protocol = TRACKER_HTTP;
        p += 7;
    } else if (strncmp(url, "https://", 8) == 0) {
        // TODO: HTTPS requires OpenSSL
        // for now treat as http
        t->protocol = TRACKER_HTTP;
        p += 8;
    }

    // Find end of host
    const char *port_start = strchr(p, ':');
    const char *path_start = strchr(p, '/');

    size_t host_len;
    if (port_start) {
        host_len = port_start - p;
    } else if (path_start) {
        host_len = path_start - p;
    } else {
        host_len = strlen(p);
    }

    t->host = malloc(host_len + 1);
    strncpy(t->host, p, host_len);
    t->host[host_len] = '\0';

    // Parse port
    if (port_start) {
        t->port = atoi(port_start + 1);
    }

    // Parse Path (important for http)
    if (path_start) {
        t->path = strdup(path_start);
    } else {
        // http needs a path (usually '/')
        t->path = strdup("/");
    }

    return t;
}

int get_tracker_addr(TrackerUrl *url, struct sockaddr_in *sa) {
    struct addrinfo hints, *res;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4

    if (url->protocol == TRACKER_HTTP) {
        hints.ai_socktype = SOCK_STREAM;
    } else {
        hints.ai_socktype = SOCK_DGRAM;
    }

    sprintf(port_str, "%d", url->port);

    int status = getaddrinfo(url->host, port_str, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return -1;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    *sa = *ipv4;

    freeaddrinfo(res);
    return 0;
}

int64_t udp_announce_connect(struct sockaddr_in *tracker_addr) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket error");
        return -1;
    }

    // set 5-second timeout so it doesn't hang forever
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Build the Request
    int32_t transaction_id = rand();
    uint64_t protocol_id = 0x41727101980; // Magic constant
    int32_t action = 0; // 0 = Connect


    // Create a raw buffer (16 bytes)
    char buffer[16];

    // Pack the data (Host -> Network Byte Order)
    uint64_t protocol_id_net = htonll(protocol_id);
    uint32_t action_net = htonl(action);
    uint32_t transaction_id_net = htonl(transaction_id);

    // Copy into buffer
    memcpy(buffer, &protocol_id_net, 8);
    memcpy(buffer + 8, &action_net, 4);
    memcpy(buffer + 12, &transaction_id_net, 4);

    // Send the Request
    printf("Sending UDP Connect Request to %s...\n", inet_ntoa(tracker_addr->sin_addr));
    ssize_t sent = sendto(sock, buffer, 16, 0,
        (struct sockaddr *)tracker_addr, sizeof(*tracker_addr));

    if (sent != 16) {
        perror("sendto failed");
        close(sock);
        return -1;
    }

    // Receive the Response
    // Response is 16 bytes: Action(4) | Transaction_ID(4) | Connection_ID(8)
    char response[16];

    // don't really need the sender's addr here, so set to null
    ssize_t received = recvfrom(sock, response, 16, 0, NULL, NULL);

    if (received < 0 ) {
        // check if it was a timeout
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("Error: Tracker timed out.\n");
        } else {
            perror("recvfrom failed");
        }
        close(sock);
        return -1;
    }

    if (received < 16) {
        printf("Error: Received partial packet (%zd bytes)\n", received);
        close(sock);
        return -1;
    }

    // Parse Response
    // Unpack data (Network -> Host Byte Order)
    uint32_t res_action = ntohl(*(uint32_t*)(response));
    uint32_t res_trans_id = ntohl(*(uint32_t*)(response + 4));
    uint64_t res_conn_id = ntohl(*(uint64_t*)(response + 8));

    // Validate Transaction ID (Must match what we sent)
    if (res_trans_id != (uint32_t)transaction_id) {
        printf("Error: Transaction ID mismatch! Sent %d, Got %d\n", transaction_id, res_trans_id);
        close(sock);
        return -1;
    }

    // Validate Action (0 = Connect)
    if (res_action != 0) {
        printf("Error: Expected Action 0 (Connect), got %d\n", res_action);
        close(sock);
        return -1;
    }

    printf("Handshake success! Connection ID: %llu\n", res_conn_id);

    close(sock);
    return res_conn_id;
}

void free_tracker_url(TrackerUrl *t) {
    if (t) {
        if (t->host) free(t->host);
        if (t->path) free(t->path);
        free(t);
    }
}
