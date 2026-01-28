#include "sign/sign.hpp"
#include <string>
#include <unordered_map>

namespace crypto {
        
    std::unordered_map<std::string, SignAlgorithm> stringToSignAlgorithm = {
        {"rsa", RSASHA256},
        {"rsasha256", RSASHA256},
        {"ecdsa", ECDSAP256SHA256},
        {"ecdsa_p256", ECDSAP256SHA256},
        {"ecdsa_p256_sha256", ECDSAP256SHA256}
    };

} // namespace crypto
