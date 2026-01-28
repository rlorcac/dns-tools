#include "nsec.hpp"
#include "rr.hpp"
#include "string_commons.hpp"
#include <set>
#include <algorithm>
#include <vector>

namespace dns {
    std::vector<DNSResourceRecord> generateNSEC(
        const std::vector<DNSResourceRecord>& records, 
        const std::string& origin,
        uint32_t ttl
    ) {
        // Get unique names
        std::set<std::string> names;
        for (const auto& rr : records) {
            names.insert(commons::toLower(rr.name));
        }
        
        std::vector<std::string> sorted_names(names.begin(), names.end());
        std::sort(sorted_names.begin(), sorted_names.end());
        
        std::vector<DNSResourceRecord> nsec_records;
        
        for (size_t i = 0; i < sorted_names.size(); i++) {
            std::string curr = sorted_names[i];
            std::string next = sorted_names[(i + 1) % sorted_names.size()];
            
            // Find types at this name
            std::set<uint16_t> types;
            for (const auto& rr : records) {
                if (commons::toLower(rr.name) == curr) {
                    types.insert(rr.type);
                }
            }
            // we're creating NSEC, so add NSEC and RRSIG types too
            types.insert(RR_TYPE_NSEC);
            types.insert(RR_TYPE_RRSIG);
            
            // Create NSEC record
            DNSResourceRecord nsec;
            nsec.name = curr;
            nsec.type = RR_TYPE_NSEC;
            nsec.ttl = ttl;
            
            // RDATA: next name + type bitmap
            auto next_encoded = commons::encodeDomainName(next);
            nsec.rdata.insert(nsec.rdata.end(), next_encoded.begin(), next_encoded.end());
            
            // Type bitmap (simplified - one window)
            uint8_t max_type = *types.rbegin();
            uint8_t bitmap_len = (max_type / 8) + 1;
            
            nsec.rdata.push_back(0); // window number
            nsec.rdata.push_back(bitmap_len);
            
            std::vector<uint8_t> bitmap(bitmap_len, 0);
            for (uint16_t type : types) {
                if (type < 256) {
                    uint8_t byte_pos = type / 8;
                    uint8_t bit_pos = 7 - (type % 8);
                    bitmap[byte_pos] |= (1 << bit_pos);
                }
            }
            
            nsec.rdata.insert(nsec.rdata.end(), bitmap.begin(), bitmap.end());
            nsec_records.push_back(nsec);
        }
        
        return nsec_records;
    }
}