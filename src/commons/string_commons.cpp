#include <string>
#include <algorithm>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <cstdint>

#include "string_commons.hpp"

namespace commons {
    
    std::string toLower(const std::string& s) {
        std::string result = "";
        for (auto& c : s) result += std::tolower(c);
        return result;
    }

    std::string toUpper(const std::string& s) {
        std::string result = "";
        for (auto& c : s) result += std::toupper(c);
        return result;
    }

    std::string escape(char c) {
        if ((int) c < 32 || (int) c > 126) {
            return "\\0x" + std::to_string((int)c);
        } else {
            return std::string(1, c);
        }
    }

    std::string escape(const std::string& s) {
        std::string result = "";
        for (auto& c : s) {
            result += escape(c);
        }
        return result;
    }

    std::vector<uint8_t> encodeDomainName(const std::string& name) {
        std::vector<uint8_t> result;
        std::istringstream iss(name);
        std::string label;
        
        while (std::getline(iss, label, '.')) {
            if (label.empty()) break; // root
            if (label.length() > 63) throw std::runtime_error("Label too long");
            result.push_back(label.length());
            result.insert(result.end(), label.begin(), label.end());
        }
        result.push_back(0); // root
        return result;
    }

}