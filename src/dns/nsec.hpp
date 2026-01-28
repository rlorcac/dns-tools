#include <vector>
#include <string>

#ifndef DNS_NSEC_HPP // DNS_NSEC_HPP
#define DNS_NSEC_HPP

#include "rr.hpp"

namespace dns {
    std::vector<DNSResourceRecord> generateNSEC(const std::vector<DNSResourceRecord>& records, const std::string& origin, uint32_t ttl);
}
#endif // DNS_NSEC_HPP