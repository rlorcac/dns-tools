#include <string>
#include <vector>

#ifndef DNS_RRSET_HPP // DNS_RRSET_HPP
#define DNS_RRSET_HPP

#include "rr.hpp"

namespace dns {
    struct RRSet {
        std::string name;
        rr_type_t type;
        rr_class_t rclass;
        uint32_t ttl;
        std::vector<DNSResourceRecord> records;
    };

    std::vector<RRSet> groupIntoRRsets(const std::vector<DNSResourceRecord>& records);

    std::vector<uint8_t> rrsetToWire(const RRSet& rrset);
}

#endif // DNS_RRSET_HPP