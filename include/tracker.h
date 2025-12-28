//
// Created by Elliot Anderson on 12/27/25.
//

#ifndef TORRENT_CLIENT_TRACKER_H
#define TORRENT_CLIENT_TRACKER_H

#pragma once
#include <stdint.h>
#include <netinet/in.h>

typedef enum { TRACKER_UDP, TRACKER_HTTP } TrackerProtocol;

typedef struct {
    char *host;
    int port;
    char *path;
    TrackerProtocol protocol;
} TrackerUrl;

typedef struct {
    uint32_t ip;
    uint16_t port;
} PeerInfo;

TrackerUrl* parse_tracker_url(const char *url);
void free_tracker_url(TrackerUrl *t);
int get_tracker_addr(TrackerUrl *url, struct sockaddr_in *sa);
int64_t udp_announce_connect(struct sockaddr_in *tracker_addr, int *out_sock);
int udp_announce_request(int sock, struct sockaddr_in *tracker_addr,
    int64_t connection_id,
    unsigned char *info_hash,
    PeerInfo **out_peers);
#endif //TORRENT_CLIENT_TRACKER_H