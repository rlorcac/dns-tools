#include "hash/digest.hpp"
#include <unordered_map>
#include <string>

std::unordered_map<std::string, DigestAlgorithm> stringToDigestAlgorithm = {
    {"sha384", SHA384},
    {"sha512", SHA512},
};