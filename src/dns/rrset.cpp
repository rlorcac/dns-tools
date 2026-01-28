#include "wire_format.hpp"
#include "rr.hpp"
#include "rrset.hpp"
#include <vector>
#include <map>
#include <tuple>
#include <algorithm>

namespace dns {
    DNSResourceRecordSetList groupIntoRRsets(const std::vector<DNSResourceRecord>& records) {
        std::map<std::tuple<std::string, uint16_t>, DNSResourceRecordSet> map;
        
        for (const auto& rr : records) {
            auto key = std::make_tuple(toLower(rr.name), rr.type);
            
            if (map.find(key) == map.end()) {
                DNSResourceRecordSet rrset;
                rrset.name = toLower(rr.name);
                rrset.type = rr.type;
                rrset.rclass = rr.rclass;
                rrset.ttl = rr.ttl;
                map[key] = rrset;
            }
            
            map[key].records.push_back(rr);
        }
        
        DNSResourceRecordSetList result;
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
        
        for (const auto& rr : rrset.records) {
            auto rr_wire = rr.toWire();
            wire.insert(wire.end(), rr_wire.begin(), rr_wire.end());
        }
        
        return wire;
    }
}