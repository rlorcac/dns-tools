#include "sign/sign.hpp"
#include "rr.hpp"
#include "rrset.hpp"
#include "wire_format.hpp"
#include "string_commons.hpp"
#include "dnssec_keys.hpp"
#include <unordered_map>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <ctime>
#include <iostream>
#include <stdexcept>

namespace crypto {
        
    std::unordered_map<std::string, SignAlgorithm> stringToSignAlgorithm = {
        // {"rsasha1", RSASHA1}, // @TODO: Mandatory per RFC 4034, but not supported by OpenSSL 3.0
        {"rsa", RSASHA256},
        {"rsasha256", RSASHA256},
        {"ecdsa", ECDSAP256SHA256},
        {"ecdsa_p256", ECDSAP256SHA256},
        {"ecdsa_p256_sha256", ECDSAP256SHA256}
    };

    DNSSECSigner::DNSSECSigner(const std::string& origin) : zsk(nullptr), ksk(nullptr), origin(origin) {}
        
    DNSSECSigner::~DNSSECSigner() {
        if (zsk) EVP_PKEY_free(zsk);
        if (ksk) EVP_PKEY_free(ksk);
    }
    
    void DNSSECSigner::generateKeys() {
        // Generate ZSK (1024-bit RSA)
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024);
        EVP_PKEY_keygen(ctx, &zsk);
        EVP_PKEY_CTX_free(ctx);
        
        // Generate KSK (2048-bit RSA)
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
        EVP_PKEY_keygen(ctx, &ksk);
        EVP_PKEY_CTX_free(ctx);
    }
        
    void DNSSECSigner::loadKeys(const std::string& zsk_file, const std::string& ksk_file) {
        FILE* fp = fopen(zsk_file.c_str(), "rb");
        zsk = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        
        fp = fopen(ksk_file.c_str(), "rb");
        ksk = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
        fclose(fp);
    }
    
    std::vector<dns::DNSResourceRecord> DNSSECSigner::getDNSKEYRecords(uint32_t ttl) {
        std::vector<dns::DNSResourceRecord> keys;
        keys.push_back(createDNSKEY(zsk, dns::DNSSEC_ZSK, ttl)); // ZSK
        keys.push_back(createDNSKEY(ksk, dns::DNSSEC_KSK, ttl)); // KSK
        return keys;
    }
        
    void DNSSECSigner::saveKeys(const std::string& zsk_file, const std::string& ksk_file) {
        FILE* fp = fopen(zsk_file.c_str(), "wb");
        PEM_write_PrivateKey(fp, this->zsk, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(fp);
        
        fp = fopen(ksk_file.c_str(), "wb");
        PEM_write_PrivateKey(fp, this->ksk, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(fp);
    }
    
    dns::DNSResourceRecord DNSSECSigner::signRRSet(const dns::DNSResourceRecordSet& rrset, uint32_t sig_validity_days = 30) {
        EVP_PKEY* key = (rrset.type == dns::RR_TYPE_DNSKEY) ? ksk : zsk;
        dns::dnssec_key_t key_type = (rrset.type == dns::RR_TYPE_DNSKEY) ? dns::DNSSEC_KSK : dns::DNSSEC_ZSK;
        
        dns::DNSResourceRecord rrsig;
        rrsig.name = rrset.name;
        rrsig.type = dns::RR_TYPE_RRSIG;
        rrsig.rclass = rrset.rclass;
        rrsig.ttl = rrset.ttl;
        
        // Build RRSIG RDATA (without signature)
        std::vector<uint8_t> rrsig_rdata;

        dns::writeUint16(rrsig_rdata, rrset.type); // type covered
        dns::writeUint8(rrsig_rdata, 8); // algorithm (RSA-SHA256)
        dns::writeUint8(rrsig_rdata, countLabels(rrset.name)); // labels
        dns::writeUint32(rrsig_rdata, rrset.ttl); // original TTL
        
        time_t now = time(nullptr);
        time_t expiration = now + (sig_validity_days * 24 * 3600);
        time_t inception = now;
        
        dns::writeUint32(rrsig_rdata, expiration);
        dns::writeUint32(rrsig_rdata, inception);
        dns::writeUint16(rrsig_rdata, calculateKeyTag(key, key_type)); // key tag
        
        std::vector<uint8_t> signer = commons::encodeDomainName(origin);
        rrsig_rdata.insert(rrsig_rdata.end(), signer.begin(), signer.end());
        
        std::vector<uint8_t> to_sign = rrsig_rdata;
        std::vector<uint8_t> rrset_wire = rrsetToWire(rrset);
        to_sign.insert(to_sign.end(), rrset_wire.begin(), rrset_wire.end());
        
        size_t sig_len = 0;
        std::cout << "Data to be signed: ";
        for (auto byte : to_sign) {
            std::cout << commons::escape(byte);
        }
        std::cout << std::endl;

        // Sign the data
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            throw std::runtime_error("Failed to allocate OpenSSL digest context");
        }

        EVP_PKEY_CTX* pkey_ctx = nullptr;
        if (EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha256(), nullptr, key) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw std::runtime_error("EVP_DigestSignInit failed");
        }

        if (pkey_ctx && EVP_PKEY_base_id(key) == EVP_PKEY_RSA) {
            if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) != 1) {
                EVP_MD_CTX_free(md_ctx);
                throw std::runtime_error("Failed to set RSA PKCS#1 padding");
            }
        }

        if (EVP_DigestSignUpdate(md_ctx, to_sign.data(), to_sign.size()) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw std::runtime_error("EVP_DigestSignUpdate failed");
        }

        if (EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw std::runtime_error("EVP_DigestSignFinal(size) failed");
        }
        std::vector<uint8_t> signature(sig_len);
        if (EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw std::runtime_error("EVP_DigestSignFinal(data) failed");
        }
        signature.resize(sig_len);
        EVP_MD_CTX_free(md_ctx);


        // Add signature
        rrsig_rdata.insert(rrsig_rdata.end(), signature.begin(), signature.end());
        rrsig.rdata = rrsig_rdata;
        
        return rrsig;
    }   

} // namespace crypto