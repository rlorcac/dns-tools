#include "commons/string_commons.hpp"
#include "dns/wire_format.hpp"
#include "dns/rr.hpp"
#include "dns/rrset.hpp"
#include <vector>
#include <map>
#include <tuple>
#include <algorithm>
#include <cstdint>

namespace dns {
    std::vector<DNSResourceRecordSet> groupIntoRRsets(const std::vector<DNSResourceRecord>& records) {
        std::map<std::tuple<std::string, uint16_t>, DNSResourceRecordSet> map;
        
        for (const auto& rr : records) {
            auto key = std::make_tuple(commons::toLower(rr.name), rr.type);
            
            if (map.find(key) == map.end()) {
                DNSResourceRecordSet rrset;
                rrset.name = commons::toLower(rr.name);
                rrset.type = rr.type;
                rrset.rclass = rr.rclass;
                rrset.ttl = rr.ttl;
                map[key] = rrset;
            }
            
            map[key].records.push_back(rr);
        }
        
        std::vector<DNSResourceRecordSet> result;
        for (auto& pair : map) {
            // Sort RRset canonically
            std::sort(pair.second.records.begin(), pair.second.records.end(),
                [](const DNSResourceRecord& a, const DNSResourceRecord& b) { return a.rdata < b.rdata; });
            result.push_back(pair.second);
        }
        
        return result;
    }

    std::vector<uint8_t> rrsetToWire(const DNSResourceRecordSet& rrset) {
        std::vector<uint8_t> wire;
        
        // For DNSSEC signing, all RRs must use the RRset's owner name and TTL
        // RFC 4034 Section 3.1.8.1
        for (const auto& rr : rrset.records) {
            // Encode owner name (canonical lowercase)
            std::vector<uint8_t> name_wire = commons::encodeDomainName(commons::toLower(rrset.name));
            wire.insert(wire.end(), name_wire.begin(), name_wire.end());
            
            // Type, class, TTL (use RRset's TTL, not individual RR's TTL)
            writeUint16(wire, rrset.type);
            writeUint16(wire, rrset.rclass);
            writeUint32(wire, rrset.ttl);
            
            // RDATA length and RDATA
            writeUint16(wire, rr.rdata.size());
            wire.insert(wire.end(), rr.rdata.begin(), rr.rdata.end());
        }
        
        return wire;
    }
}