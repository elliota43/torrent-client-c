# C Torrent Client

Current features:

- Supports single and multi-file torrents
- **Asynchronous I/O Engine:** non-blocking `salect()` event loop. Handles 50+ concurrent peer connections on a single thread with zero context-switching.
- **Request Pipelining**
- **Magnet Link Support:** BEP 9 (Extension Protocol) to handshake and fetch metadata without .torrent files.
- UDP Tracker Protocol (BEP 15)
- Connection Pool replenishes stalled/choked connections automatically and performs async scans to find faster peers.
- Integrity Checking - SHA-1 hash to verify pieces before downloading
- Capable of parsing Multi-file metadata & mapping blocks to the correct file offsets on disk.

## TODO

- Prioritize rare pieces
- Add Network Byte Order helper functions for systems that don't come native with one `htols()`, etc.
- **Seeding!**
- Parse bencode in BEP 10 Extension Handshake Response (`metadata.c`)
- **Resume Capability**: save bitfield state to disk and resume downloads after restarting.

## Install

To compile and run:

```
git clone https://github.com/elliota43/torrent-client-c.git/

cd torrent-client-c

cmake --build .

./torrent-client
```

**Note**: Deprecation warnings are silenced because SHA1 is technically deprecated, but is essential to the [BitTorrent protocol](https://www.bittorrent.org/beps/bep_0003.html).