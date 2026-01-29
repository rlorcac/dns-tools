#include <string>
#include <algorithm>
#include <vector>
#include <sstream>
#include <stdexcept>

#ifndef COMMONS_STRING_COMMONS_HPP // COMMONS_STRING_COMMONS_HPP
#define COMMONS_STRING_COMMONS_HPP

namespace commons {
    
    std::string toLower(const std::string& s);

    std::string toUpper(const std::string& s);

    std::string escape(char c);

    std::string escape(const std::string& s);

    std::vector<uint8_t> parseIPv4(const std::string& ip);

    std::vector<uint8_t> parseIPv6(const std::string& ip);

    uint32_t parseTimestamp(const std::string& timestamp_str);

    // DNS name encoding
    std::vector<uint8_t> encodeDomainName(const std::string& name);
    
    std::string decodeDomainName(const std::vector<uint8_t>& rdata, size_t& offset);

    std::string encodeBase64(const std::vector<uint8_t>& data);

    std::vector<uint8_t> decodeBase64(const std::string& encoded);
}

#endif // COMMONS_STRING_COMMONS_HPP