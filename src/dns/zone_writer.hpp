#include <string>
#include <vector>
#include <ostream>

#ifndef DNS_ZONE_WRITER_HPP // DNS_ZONE_WRITER_HPP
#define DNS_ZONE_WRITER_HPP

#include "rr.hpp"
#include "wire_format.hpp"
#include "string_commons.hpp"

namespace dns {

    class ZoneWriter {
    public:
        void writeZoneFile(const std::string& filename, const std::vector<DNSResourceRecord>& records, const std::string& origin);
    private:
        void writeRecord(std::ostream& os, const DNSResourceRecord& rr, const std::string& origin) {
            os << rr.name << "\t" << rr.ttl << "\t" 
            << rr.rclass << "\t" << rr.type << "\t";
            writeRData(os, rr.type, rr.rdata);
            os << "\n";
        }

        void writeRData(std::ostream& os, rr_type_t type, const std::vector<uint8_t>& rdata) {
            // Implementation for writing RDATA based on type
            switch (type) {
                case RR_TYPE_A:
                    writeA(os, rdata);
                    break;
                case RR_TYPE_NS: case RR_TYPE_CNAME:
                    writeNS_CNAME(os, rdata); // CNAME has same format as NS
                    break;
                case RR_TYPE_SOA:
                    writeSOA(os, rdata);
                    break;
                case RR_TYPE_MX:
                    writeMX(os, rdata); // MX RDATA starts with preference then domain name
                    break;
                case RR_TYPE_AAAA:
                    writeAAAA(os, rdata);
                    break;
                case RR_TYPE_TXT:
                    writeTXT(os, rdata);
                    break;
                case RR_TYPE_DS:
                    writeDS(os, rdata);
                    break;
                case RR_TYPE_RRSIG:
                    writeRRSIG(os, rdata);
                    break;
                case RR_TYPE_NSEC:
                    writeNSEC(os, rdata);
                    break;
                case RR_TYPE_DNSKEY:
                    writeDNSKEY(os, rdata);
                    break;
                default:
                    os << commons::escape(std::string(rdata.begin(), rdata.end()));
                    break;
            }
        }

        void writeA(std::ostream& os, const std::vector<uint8_t>& rdata) {
            if (rdata.size() != 4) {
                throw std::runtime_error("Invalid RDATA size for A record");
            }
            os << static_cast<int>(rdata[0]) << "."
               << static_cast<int>(rdata[1]) << "."
               << static_cast<int>(rdata[2]) << "."
               << static_cast<int>(rdata[3]);
        }

        void writeNS_CNAME(std::ostream& os, const std::vector<uint8_t>& rdata) {
            size_t offset = 0;
            std::string nsdname = commons::decodeDomainName(rdata, offset);
            os << nsdname;
        }

        void writeSOA(std::ostream& os, const std::vector<uint8_t>& rdata) {
            size_t offset = 0;
            std::string mname = commons::decodeDomainName(rdata, offset);
            std::string rname = commons::decodeDomainName(rdata, offset);
            
            uint32_t serial = readUint32(rdata.data(), offset);
            uint32_t refresh = readUint32(rdata.data(), offset);
            uint32_t retry = readUint32(rdata.data(), offset);
            uint32_t expire = readUint32(rdata.data(), offset);
            uint32_t minimum = readUint32(rdata.data(), offset);
            
            os << mname << " " << rname << " "
               << serial << " " << refresh << " "
               << retry << " " << expire << " "
               << minimum;
        }

        void writeMX(std::ostream& os, const std::vector<uint8_t>& rdata) {
            if (rdata.size() < 3) {
                throw std::runtime_error("Invalid RDATA size for MX record");
            }
            size_t offset = 0;
            uint16_t preference = (rdata[offset] << 8) | rdata[offset + 1];
            offset += 2;
            std::string exchange = commons::decodeDomainName(rdata, offset);
            os << preference << " " << exchange;
        }

        void writeAAAA(std::ostream& os, const std::vector<uint8_t>& rdata) {
            if (rdata.size() != 16) {
                throw std::runtime_error("Invalid RDATA size for AAAA record");
            }
            for (size_t i = 0; i < 16; i += 2) {
                if (i > 0) os << ":";
                os << std::hex << ((rdata[i] << 8) | rdata[i + 1]);
            }
            os << std::dec; // Reset to decimal
        }

        void writeTXT(std::ostream& os, const std::vector<uint8_t>& rdata) {
            size_t offset = 0;
            while (offset < rdata.size()) {
                uint8_t len = rdata[offset++];
                if (offset + len > rdata.size()) {
                    throw std::runtime_error("Invalid TXT record: length exceeds RDATA size");
                }
                std::string txt_part(rdata.begin() + offset, rdata.begin() + offset + len);
                os << "\"" << commons::escape(txt_part) << "\" ";
                offset += len;
            }
        }

        void writeDS(std::ostream& os, const std::vector<uint8_t>& rdata) {
            if (rdata.size() < 4) {
                throw std::runtime_error("Invalid RDATA size for DS record");
            }
            size_t offset = 0;
            uint16_t key_tag = (rdata[offset] << 8) | rdata[offset + 1];
            offset += 2;
            uint8_t algorithm = rdata[offset++];
            uint8_t digest_type = rdata[offset++];
            std::string digest;
            for (; offset < rdata.size(); offset++) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02X", rdata[offset]);
                digest += buf;
            }
            os << key_tag << " " << static_cast<int>(algorithm) << " "
               << static_cast<int>(digest_type) << " " << digest;
        }

        void writeNSEC(std::ostream& os, const std::vector<uint8_t>& rdata) {
            // Implementation for writing NSEC RDATA
            size_t offset = 0;
            std::string next_domain = commons::decodeDomainName(rdata, offset);
            os << next_domain << " ";
            // Type bitmap parsing
            while (offset < rdata.size()) {
                uint8_t window = rdata[offset++];
                uint8_t len = rdata[offset++];
                for (uint8_t i = 0; i < len; i++) {
                    uint8_t bitmap = rdata[offset + i];
                    for (int bit = 0; bit < 8; bit++) {
                        if (bitmap & (1 << (7 - bit))) {
                            uint16_t type_code = window * 256 + i * 8 + bit;
                            os << (rr_type_t) type_code << " ";
                        }
                    }
                }
                offset += len;
            }
        }

        void writeRRSIG(std::ostream& os, const std::vector<uint8_t>& rdata) {
            if (rdata.size() < 18) {
                throw std::runtime_error("Invalid RRSIG record: too short");
            }

            size_t offset = 0;

            // Type Covered (2 bytes)
            uint16_t type_covered = (rdata[offset] << 8) | rdata[offset + 1];
            offset += 2;

            // Algorithm (1 byte)
            uint8_t algorithm = rdata[offset];
            offset += 1;

            // Labels (1 byte)
            uint8_t labels = rdata[offset];
            offset += 1;

            // Original TTL (4 bytes)
            uint32_t orig_ttl = (rdata[offset] << 24) | (rdata[offset + 1] << 16) |
                                (rdata[offset + 2] << 8) | rdata[offset + 3];
            offset += 4;

            // Signature Expiration (4 bytes)
            uint32_t sig_exp = (rdata[offset] << 24) | (rdata[offset + 1] << 16) |
                               (rdata[offset + 2] << 8) | rdata[offset + 3];
            offset += 4;

            // Signature Inception (4 bytes)
            uint32_t sig_inc = (rdata[offset] << 24) | (rdata[offset + 1] << 16) |
                               (rdata[offset + 2] << 8) | rdata[offset + 3];
            offset += 4;

            // Key Tag (2 bytes)
            uint16_t key_tag = (rdata[offset] << 8) | rdata[offset + 1];
            offset += 2;

            // Signer's Name (variable length domain name)
            std::string signer_name = commons::decodeDomainName(rdata, offset);

            // Signature (remaining bytes)
            std::vector<uint8_t> signature(rdata.begin() + offset, rdata.end());
            std::string sig_b64 = commons::encodeBase64(signature);

            // Output in pretty format
            os << (dns::rr_type_t) type_covered << " " << static_cast<int>(algorithm) << " "
               << static_cast<int>(labels) << " " << orig_ttl << " "
               << sig_exp << " " << sig_inc << " " << key_tag << " "
               << signer_name << " " << sig_b64;
        }

        void writeDNSKEY(std::ostream& os, const std::vector<uint8_t>& rdata) {
            if (rdata.size() < 4) {
                throw std::runtime_error("Invalid DNSKEY record: too short");
            }

            size_t offset = 0;

            // Flags (2 bytes)
            uint16_t flags = (rdata[offset] << 8) | rdata[offset + 1];
            offset += 2;

            // Protocol (1 byte)
            uint8_t protocol = rdata[offset];
            offset += 1;

            // Algorithm (1 byte)
            uint8_t algorithm = rdata[offset];
            offset += 1;

            // Public Key (remaining bytes)
            std::vector<uint8_t> public_key(rdata.begin() + offset, rdata.end());
            std::string pubkey_b64 = commons::encodeBase64(public_key);

            // Output in pretty format
            os << flags << " " << static_cast<int>(protocol) << " "
               << static_cast<int>(algorithm) << " " << pubkey_b64;
        }

    };

} // namespace dns

#endif // DNS_ZONE_WRITER_HPP