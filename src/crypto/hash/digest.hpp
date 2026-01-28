#include <unordered_map>
#include <string>
#include <cstdint>

#ifndef CRYPTO_DIGEST_HPP // CRYPTO_DIGEST_HPP
#define CRYPTO_DIGEST_HPP

namespace crypto {
    typedef int DigestAlgorithm;

    enum : DigestAlgorithm {
        SHA384 = 1,
        SHA512 = 2,
    };

    extern std::unordered_map<std::string, DigestAlgorithm> stringToDigestAlgorithm;
}
#endif // CRYPTO_DIGEST_HPP