#include <iostream>
#include <unordered_set>
#include <string>
#include <ctime>
#include <cstdint>

#ifndef CONTEXT_HPP // CONTEXT_HPP
#define CONTEXT_HPP

#include "sign/sign.hpp"
#include "hash/digest.hpp"

struct DigestOptions {
    // digest command options
    std::string file;
    DigestAlgorithm hashDigest = SHA384;
    bool info = false;
    std::string output;
    std::string zone;
};

struct SignOptions {
    // sign command options
    bool createKeys = false;
    bool digest = false;
    std::string file;
    DigestAlgorithm hashDigest = SHA384;
    bool lazy = false;
    bool NSEC3 = false;
    uint16_t NSEC3Iterations;
    uint16_t NSEC3SaltLength = 64;
    std::string NSEC3SaltValue;
    bool optOut = false;
    std::string rrsigDuration;
    std::string rrsigExpirationDate;
    SignAlgorithm signAlgorithm = RSASHA256;
    std::string verifyThresholdDate;
    std::string verifyThresholdDuration;
    std::string zone;
};

struct VerifyOptions {
    // verify command options
    std::string file;
    bool skipDigests = false;
    bool skipSignatures = false;
    std::string thresholdDate;
    std::string thresholdDuration;
    std::string zone;
};

struct AllOptions {
    // global options
    std::string config;
    // digest command options
    DigestOptions digest;
    // sign command options
    SignOptions sign;
    // verify command options
    VerifyOptions verify;
};

std::shared_ptr<AllOptions> OPTION_STRUCT = std::make_shared<AllOptions>();

#endif // CONTEXT_HPP
