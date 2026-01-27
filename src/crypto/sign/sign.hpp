#include <string>
#include <cstdint>
#include <unordered_map>

#ifndef CRYPTO_SIGN_HPP // CRYPTO_SIGN_HPP
#define CRYPTO_SIGN_HPP

typedef uint8_t SignAlgorithm;

enum : SignAlgorithm {
    RSASHA256 = 8,
    ECDSAP256SHA256 = 13,
};

std::unordered_map<std::string, SignAlgorithm> stringToSignAlgorithm = {
    {"rsa", RSASHA256},
    {"rsasha256", RSASHA256},
    {"ecdsa", ECDSAP256SHA256},
    {"ecdsa_p256", ECDSAP256SHA256},
    {"ecdsa_p256_sha256", ECDSAP256SHA256}
};

#endif // CRYPTO_SIGN_HPP
