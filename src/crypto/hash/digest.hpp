#ifndef CRYPTO_DIGEST_HPP // CRYPTO_DIGEST_HPP
#define CRYPTO_DIGEST_HPP

typedef uint8_t DigestAlgorithm;

enum : DigestAlgorithm {
    SHA384 = 1,
    SHA512 = 2,
};

std::unordered_map<std::string, DigestAlgorithm> stringToDigestAlgorithm = {
    {"sha384", SHA384},
    {"sha512", SHA512},
};

#endif // CRYPTO_DIGEST_HPP