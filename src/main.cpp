#include <iostream>
#include <string>
#include "net/echo_server.h"

static void print_help() {
    std::cout << "MiniHTTP " << PROJECT_VERSION << "\n"
              << "Usage: minihttp [--help] [--version]\n";
}

int main(int argc, char** argv) {
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "--help") { print_help(); return 0; }
        if (arg == "--version") { std::cout << PROJECT_VERSION << "\n"; return 0; }
    }
    std::cout << "MiniHTTP boot OK. Use --help for options.\n";
    int port = 8080;
    if (argc == 2) {
        port = std::stoi(argv[1]);
    }
    EchoServer s(port);
    s.run();
    return 0;
}
