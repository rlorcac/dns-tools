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

    // DNS name encoding
    std::vector<uint8_t> encodeDomainName(const std::string& name);

}

#endif // COMMONS_STRING_COMMONS_HPP