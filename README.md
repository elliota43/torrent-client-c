# C Torrent Client

Current features:

- Supports single and multi-file torrents
- Parallel Worker Threads that download pieces from different peers.
- Magnet Link Downloads

## TODO

- Prioritize rare pieces
- Add Network Byte Order helper functions for systems that don't come native with one `htols()`, etc.
- **Seeding!**
- Parse bencode in BEP 10 Extension Handshake Response (`metadata.c`)