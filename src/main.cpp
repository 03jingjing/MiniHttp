#include <iostream>
#include <string>

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
    return 0;
}
