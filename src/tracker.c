//
// Created by Elliot Anderson on 12/27/25.
//

#include "tracker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

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
