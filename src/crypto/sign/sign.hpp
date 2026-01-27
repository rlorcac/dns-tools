#include <string>
#include <cstdint>
#include <unordered_map>

#ifndef CRYPTO_SIGN_HPP // CRYPTO_SIGN_HPP
#define CRYPTO_SIGN_HPP

typedef int SignAlgorithm;

enum : SignAlgorithm {
    RSASHA256 = 8,
    ECDSAP256SHA256 = 13,
};

extern std::unordered_map<std::string, SignAlgorithm> stringToSignAlgorithm;

#endif // CRYPTO_SIGN_HPP
