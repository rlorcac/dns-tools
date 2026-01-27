#include <iostream>
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

struct SignFileOptions {
    // sign file command options
    std::string kskFile = "ksk.pem";
    std::string zskFile = "zsk.pem";
};

struct SignPKCS11Options {
    // sign pkcs11 command options
    std::string keyLabel = "HSM-tools";
    std::string p11lib;
    std::string userKey = "1234";
};

struct SignOptions {
    // file signing options
    SignFileOptions fileOptions;
    // pkcs11 signing options
    SignPKCS11Options pkcs11Options;
    // sign command options
    bool createKeys = false;
    bool digest = false;
    std::string file;
    DigestAlgorithm hashDigest = SHA384;
    bool info = false;
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
    std::string output;
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
