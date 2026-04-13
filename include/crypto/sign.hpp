#include "dns/rr.hpp"
#include "dns/rrset.hpp"
#include "dns/wire_format.hpp"
#include "dns/dnssec_keys.hpp"
#include "commons/string_commons.hpp"
#include <unordered_map>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <ctime>

#ifndef CRYPTO_SIGN_HPP // CRYPTO_SIGN_HPP
#define CRYPTO_SIGN_HPP

namespace crypto {

    typedef int SignAlgorithm;

    enum : SignAlgorithm {
        // RSASHA1 = 5, // @TODO: Mandatory per RFC 4034, but not supported by OpenSSL 3.0
        RSASHA256 = 8,
        ECDSAP256SHA256 = 13,
    };

    extern std::unordered_map<std::string, SignAlgorithm> stringToSignAlgorithm;

    class DNSSECSigner {
    private:
        EVP_PKEY* zsk;
        EVP_PKEY* ksk;
        std::string origin;
    public:
        DNSSECSigner(const std::string& origin);
        
        ~DNSSECSigner();
        
        void generateKeys();

        void loadKeys(const std::string& zsk_file, const std::string& ksk_file);

        std::vector<dns::DNSResourceRecord> getDNSKEYRecords(uint32_t ttl);

        void saveKeys(const std::string& zsk_file, const std::string& ksk_file);

        dns::DNSResourceRecord signRRSet(dns::DNSResourceRecordSet& rrset, uint32_t sig_validity_days);
        
    private:
        dns::DNSResourceRecord createDNSKEY(EVP_PKEY* key, uint16_t flags, uint32_t ttl, uint8_t algorithm = 8, uint8_t protocol = 3) {
            dns::DNSResourceRecord dnskey;
            dnskey.name = origin;
            dnskey.type = dns::RR_TYPE_DNSKEY;
            dnskey.rclass = dns::RR_CLASS_IN;
            dnskey.ttl = ttl;
            
            dns::writeUint16(dnskey.rdata, flags);
            dns::writeUint8(dnskey.rdata, protocol); // protocol
            dns::writeUint8(dnskey.rdata, algorithm); // algorithm
            // Extract RSA public key using modern EVP API
            BIGNUM *n = nullptr, *e = nullptr;
            if (!EVP_PKEY_get_bn_param(key, "n", &n) || !EVP_PKEY_get_bn_param(key, "e", &e)) {
                // Handle error
                BN_free(n);
                BN_free(e);
                return dnskey;
            }
            
            size_t e_len = BN_num_bytes(e);
            size_t n_len = BN_num_bytes(n);
            
            std::vector<uint8_t> e_bytes(e_len);
            std::vector<uint8_t> n_bytes(n_len);
            
            BN_bn2bin(e, e_bytes.data());
            BN_bn2bin(n, n_bytes.data());
            
            if (e_len <= 255) {
                dns::writeUint8(dnskey.rdata, e_len);
            } else {
                dns::writeUint8(dnskey.rdata, 0);
                dns::writeUint16(dnskey.rdata, e_len);
            }
            
            dnskey.rdata.insert(dnskey.rdata.end(), e_bytes.begin(), e_bytes.end());
            dnskey.rdata.insert(dnskey.rdata.end(), n_bytes.begin(), n_bytes.end());
            
            // Free BIGNUMs
            BN_free(n);
            BN_free(e);
            
            return dnskey;
        }
        
        uint16_t calculateKeyTag(EVP_PKEY* key, dns::dnssec_key_t key_type, uint32_t ttl = 3600) {
            dns::DNSResourceRecord dnskey = createDNSKEY(key, key_type, ttl);
            
            uint32_t ac = 0;
            for (size_t i = 0; i < dnskey.rdata.size(); i++) {
                ac += (i & 1) ? dnskey.rdata[i] : (dnskey.rdata[i] << 8);
            }
            ac += (ac >> 16) & 0xFFFF;
            return ac & 0xFFFF;
        }
        
        uint8_t countLabels(const std::string& name) {
            if (name.empty() || name == ".") return 0;
            
            uint8_t count = 1; // Start with 1 label
            std::string n = name;
            
            // Remove trailing dot if present
            if (n.back() == '.') {
                n.pop_back();
            }
            
            // Count dots (each dot separates labels)
            for (char c : n) {
                if (c == '.') count++;
            }
            
            return count;
        }
    };
}

#endif // CRYPTO_SIGN_HPP
