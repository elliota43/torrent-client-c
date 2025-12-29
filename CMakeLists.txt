cmake_minimum_required(VERSION 3.20)
project(torrent_client C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

file(GLOB SOURCES "src/*.c")

add_compile_options(-Wno-deprecated-declarations)

add_executable(torrent_client
        main.c
        src/bencode.c
        src/tracker.c
        src/peer.c
        src/bitfield.c
        src/client_state.c
        src/magnet.c
        src/metadata.c
        src/connection_manager.c
)

find_package(OpenSSL REQUIRED)
target_link_libraries(torrent_client PRIVATE OpenSSL::Crypto)