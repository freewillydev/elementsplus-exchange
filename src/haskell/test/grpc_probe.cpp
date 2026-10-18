// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <haskell/bridge.h>
#include <chrono>
#include <iostream>

int main(int argc, char** argv)
{
    if (argc != 6) return 2;
    const std::string directory{argv[2]}, mode{argv[5]};
    const auto start = std::chrono::steady_clock::now();
    const auto result = drivechain::haskell::GrpcRequest(std::array<std::string,7>{
        argv[3], argv[4], argv[1], directory + "/ca.pem",
        directory + "/elements-client.pem", directory + "/elements-client-key.pem",
        mode == "wrong-authority" ? "wrong.invalid" : "enforcer.local"},
        mode == "deadline" ? 100 : 2000, 65536, [&] {
            return mode == "cancel" && std::chrono::steady_clock::now() - start > std::chrono::milliseconds{100};
        });
    std::cout << result.status << '\n' << result.output << '\n';
    return 0;
}
