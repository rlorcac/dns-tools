#include <string>
#include <algorithm>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <iomanip>

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
            std::ostringstream oss;
            oss << "\\0x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
            return oss.str();
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

    std::vector<uint8_t> parseIPv4(const std::string& ip) {
        std::vector<uint8_t> bytes;
        std::istringstream iss(ip);
        std::string octet;
        
        while (std::getline(iss, octet, '.')) {
            int val = std::stoi(octet);
            if (val < 0 || val > 255) {
                throw std::runtime_error("Invalid IPv4 address: " + ip);
            }
            bytes.push_back(static_cast<uint8_t>(val));
        }
        
        if (bytes.size() != 4) {
            throw std::runtime_error("Invalid IPv4 address: " + ip);
        }
        
        return bytes;
    }

    std::vector<uint8_t> parseIPv6(const std::string& ip) {
        std::vector<uint8_t> bytes;
        bool has_double_colon = false;
        size_t double_colon_pos = 0;
        
        // Split by ':' and process
        std::vector<std::string> segments;
        size_t pos = 0;
        
        while (pos < ip.length()) {
            if (ip[pos] == ':') {
                if (pos + 1 < ip.length() && ip[pos + 1] == ':') {
                    if (has_double_colon) {
                        throw std::runtime_error("Invalid IPv6 address: multiple '::'");
                    }
                    has_double_colon = true;
                    double_colon_pos = segments.size();
                    pos += 2;
                    continue;
                }
                pos++;
                continue;
            }
            
            size_t next_colon = ip.find(':', pos);
            if (next_colon == std::string::npos) next_colon = ip.length();
            
            std::string segment = ip.substr(pos, next_colon - pos);
            if (!segment.empty()) {
                segments.push_back(segment);
            }
            pos = next_colon;
        }
        
        // Convert segments to bytes
        for (const auto& segment : segments) {
            int val = std::stoi(segment, nullptr, 16);
            if (val < 0 || val > 0xFFFF) {
                throw std::runtime_error("Invalid IPv6 segment: " + segment);
            }
            bytes.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
            bytes.push_back(static_cast<uint8_t>(val & 0xFF));
        }
        
        // Handle '::' expansion
        if (has_double_colon) {
            int missing_segments = 8 - segments.size();
            if (missing_segments < 0) {
                throw std::runtime_error("Invalid IPv6 address: too many segments");
            }
            size_t insert_pos = double_colon_pos * 2;
            bytes.insert(bytes.begin() + insert_pos, missing_segments * 2, 0);
        }
        
        if (bytes.size() != 16) {
            std::cerr << "Bytes size: " << bytes.size() << " for IPv6: " << ip << "\n";
            throw std::runtime_error("Invalid IPv6 address: " + ip);
        }
        
        return bytes;
    }

    uint32_t parseTimestamp(const std::string& timestamp_str) {
        if (timestamp_str.length() != 14) {
            throw std::runtime_error("Invalid timestamp format: " + timestamp_str);
        }
        
        int year = std::stoi(timestamp_str.substr(0, 4));
        int month = std::stoi(timestamp_str.substr(4, 2));
        int day = std::stoi(timestamp_str.substr(6, 2));
        int hour = std::stoi(timestamp_str.substr(8, 2));
        int minute = std::stoi(timestamp_str.substr(10, 2));
        int second = std::stoi(timestamp_str.substr(12, 2));
        
        struct tm timeinfo = {};
        timeinfo.tm_year = year - 1900;
        timeinfo.tm_mon = month - 1;
        timeinfo.tm_mday = day;
        timeinfo.tm_hour = hour;
        timeinfo.tm_min = minute;
        timeinfo.tm_sec = second;
        timeinfo.tm_isdst = -1;
        
        time_t timestamp = mktime(&timeinfo);
        if (timestamp == -1) {
            throw std::runtime_error("Invalid timestamp: " + timestamp_str);
        }
        
        return static_cast<uint32_t>(timestamp);
    }

    std::vector<uint8_t> encodeDomainName(const std::string& name) {
        std::string lower = toLower(name);
        std::vector<uint8_t> result;
        std::istringstream iss(lower);
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

    std::string decodeDomainName(const std::vector<uint8_t>& rdata, size_t& offset) {
            std::string name;
            while (offset < rdata.size()) {
                uint8_t len = rdata[offset];
                offset++;

                if (len == 0) {
                    break;  // Root label
                }

                if (offset + len > rdata.size()) {
                    throw std::runtime_error("Invalid domain name: label length exceeds RDATA size");
                }

                if (!name.empty()) {
                    name += ".";
                }

                name.append(reinterpret_cast<const char*>(&rdata[offset]), len);
                offset += len;
            }
            name += ".";
            return name;
        }
    
    std::string encodeBase64(const std::vector<uint8_t>& data) {
        static const char* base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
        
        std::string result;
        int val = 0, valb = -6;
        for (uint8_t c : data) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while (result.size() % 4) result.push_back('=');
        return result;
    }

    std::vector<uint8_t> decodeBase64(const std::string& encoded) {
        static const std::string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        std::vector<uint8_t> decoded;
        std::vector<int> T(256, -1);
        
        for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;
        
        int val = 0, valb = -8;
        for (unsigned char c : encoded) {
            if (T[c] == -1) continue;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                decoded.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        
        return decoded;
    }
    
}