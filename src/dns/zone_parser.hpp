#include <vector>
#include <string>
#include <fstream>
#include <unordered_map>
#include <ctime>
#include <algorithm>
#include <map>
#include <set>
#include <iostream>


#ifndef DNS_ZONE_PARSER_HPP // DNS_ZONE_PARSER_HPP
#define DNS_ZONE_PARSER_HPP

#include "wire_format.hpp"
#include "rr.hpp"
#include "string_commons.hpp"


namespace dns {
    class SimpleZoneParser {
    public:
        std::vector<DNSResourceRecord> parse(const std::string& filename, const std::string& origin);
    private:
        std::ifstream file;

        std::string last_owner_name = "";
        bool last_owner_name_initialized = false;

        uint32_t default_ttl;
        bool default_ttl_initialized = false;

        std::string origin = "";
        bool origin_initialized = false;

        void cleanupLine(std::string& line) {
            // Strip comments
            size_t comment = line.find(';');
            if (comment != std::string::npos) {
                line = line.substr(0, comment);
            }
        }

        void scanForDirectives(const std::string& filename) {
            file.open(filename);
            if (!file) throw std::runtime_error("Cannot open file");
            std::string line;
            while (std::getline(file, line)) {
                cleanupLine(line);
                if (line.empty()) continue;
                // Check for $TTL directive
                if (line[0] == '$') {
                    std::istringstream iss(line);
                    std::string directive;
                    iss >> directive; // $ORIGIN or $TTL
                    if (directive == "$ORIGIN" && !origin_initialized) {
                        std::string __origin;
                        iss >> __origin;
                        if (!__origin.empty() && __origin.back() != '.') {
                            throw std::runtime_error("Origin must be a fully qualified domain name");
                        }
                        else {
                            origin = __origin;
                            origin_initialized = true;
                        }
                    } else if (directive == "$TTL" && !default_ttl_initialized) {
                        std::string ttl_str;
                        iss >> ttl_str;
                        default_ttl = std::stoul(ttl_str);
                        default_ttl_initialized = true;
                    }
                }
            }
            file.close();
        }

        std::string readMultiLineRecord(std::string first_line) {
        // Remove opening parenthesis
        size_t open_paren = first_line.find('(');
        first_line.erase(open_paren, 1);
        
        std::string full_line = first_line;
        
        // Check if closing paren is on same line
        if (first_line.find(')') != std::string::npos) {
            size_t close_paren = full_line.find(')');
            full_line.erase(close_paren, 1);
            return full_line;
        }
        
        // Read until closing parenthesis
        std::string next_line;
        while (std::getline(file, next_line)) {
            // Strip comments
            size_t comment = next_line.find(';');
            if (comment != std::string::npos) {
                next_line = next_line.substr(0, comment);
            }
            
            // Trim
            next_line.erase(0, next_line.find_first_not_of(" \t"));
            next_line.erase(next_line.find_last_not_of(" \t\r\n") + 1);
            
            if (next_line.empty()) continue;
            
            size_t close_paren = next_line.find(')');
            if (close_paren != std::string::npos) {
                // Found closing paren
                next_line.erase(close_paren, 1);
                full_line += " " + next_line;
                break;
            }
            
            full_line += " " + next_line;
        }
        
        return full_line;
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

        DNSResourceRecord parseRR(const std::string& line) {
            std::istringstream iss(line);
            DNSResourceRecord rr;
            
            std::string token;
            // Check if line starts with whitespace (blank name field)
            bool blank_name = !line.empty() && (line[0] == ' ' || line[0] == '\t');
            iss >> token;
            
            // Name
            if (blank_name) {
                // Inherit from previous record
                if (!last_owner_name_initialized) {
                    throw std::runtime_error("Blank owner name with no previous record");
                }
                rr.name = last_owner_name;
            } else {
                // Parse the name
                if (token == "@") {
                    rr.name = origin;
                } else {
                    token = commons::toLower(token);
                    rr.name = token;
                    if (!rr.name.empty() && rr.name.back() != '.') {
                        rr.name += "." + origin;
                    }
                }
                // Update last owner name
                last_owner_name = rr.name;
                last_owner_name_initialized = true;
            }
            
            // If we used the name, get next token; otherwise token already has the next field
            if (!blank_name) {
                iss >> token;
            }
            // Check if next token is TTL (numeric) or CLASS (IN/OUT/etc)
            size_t pos = iss.tellg();
            
            bool token_is_numeric = !token.empty() && std::all_of(token.begin(), token.end(), ::isdigit);
            
            if (token_is_numeric) {
                // Token is TTL
                rr.ttl = std::stoul(token);
                
                // Class
                iss >> token; // IN expected
            }  else {
                // Token is CLASS, use default TTL
                if (!default_ttl_initialized) {
                    throw std::runtime_error("Default TTL not set for record without explicit TTL");
                }
                rr.ttl = default_ttl;
            }
                rr.rclass = parseClass(token);
            
            // Type
            iss >> token;
            rr.type = parseType(token);
            
            // RDATA
            rr.rdata = parseRData(rr.type, iss, origin);
            
            return rr;
        }
        
        std::vector<uint8_t> parseRData(uint16_t type, std::istringstream& iss, const std::string& origin) {
            std::vector<uint8_t> rdata;
            
            switch (type) {
                case RR_TYPE_A: {
                    std::string ip;
                    iss >> ip;
                    rdata = parseIPv4(ip);
                    break;
                }
                case RR_TYPE_NS: case RR_TYPE_CNAME: {
                    std::string name;
                    iss >> name;
                    if (!name.empty() && name.back() != '.') name += "." + origin;
                    rdata = commons::encodeDomainName(name);
                    break;
                }
                case RR_TYPE_SOA: {
                    std::string mname, rname;
                    uint32_t serial, refresh, retry, expire, minimum;
                    iss >> mname >> rname >> serial >> refresh >> retry >> expire >> minimum;
                    
                    if (!mname.empty() && mname.back() != '.') mname += "." + origin;
                    if (!rname.empty() && rname.back() != '.') rname += "." + origin;
                    
                    auto mname_enc = commons::encodeDomainName(mname);
                    auto rname_enc = commons::encodeDomainName(rname);
                    
                    rdata.insert(rdata.end(), mname_enc.begin(), mname_enc.end());
                    rdata.insert(rdata.end(), rname_enc.begin(), rname_enc.end());
                    writeUint32(rdata, serial);
                    writeUint32(rdata, refresh);
                    writeUint32(rdata, retry);
                    writeUint32(rdata, expire);
                    writeUint32(rdata, minimum);
                    break;
                }
                case RR_TYPE_MX: {
                    std::string pref, exchange;
                    iss >> pref >> exchange;
                    if (!exchange.empty() && exchange.back() != '.') exchange += "." + origin;
                    
                    writeUint16(rdata, std::stoi(pref));
                    auto exch = commons::encodeDomainName(exchange);
                    rdata.insert(rdata.end(), exch.begin(), exch.end());
                    break;
                }
                case RR_TYPE_TXT: {
                    std::string txt;
                    std::getline(iss, txt);
                    // Remove quotes
                    size_t first = txt.find_first_not_of(" \t\"");
                    size_t last = txt.find_last_not_of(" \t\"");
                    if (first != std::string::npos && last != std::string::npos) {
                        txt = txt.substr(first, last - first + 1);
                    } else {
                        txt.clear();
                    }
                    
                    rdata.push_back(txt.length());
                    rdata.insert(rdata.end(), txt.begin(), txt.end());
                    break;
                }
                case RR_TYPE_AAAA: {
                    std::string ip;
                    iss >> ip;
                    rdata = parseIPv6(ip);
                    break;
                }
                case RR_TYPE_DS: {
                    uint16_t key_tag;
                    uint8_t algorithm, digest_type;
                    std::string digest_hex;
                    
                    iss >> key_tag >> algorithm >> digest_type >> digest_hex;
                    
                    writeUint16(rdata, key_tag);
                    writeUint8(rdata, algorithm);
                    writeUint8(rdata, digest_type);
                    
                    // Parse hex digest
                    for (size_t i = 0; i < digest_hex.length(); i += 2) {
                        std::string byte_str = digest_hex.substr(i, 2);
                        uint8_t byte = std::stoi(byte_str, nullptr, 16);
                        rdata.push_back(byte);
                    }
                    break;
                }

                case RR_TYPE_RRSIG: {
                    // Format: type_covered algorithm labels original_ttl 
                    //         sig_expiration sig_inception key_tag signer_name signature
                    
                    std::string type_covered, algorithm, labels, orig_ttl;
                    std::string sig_exp, sig_inc, key_tag, signer;
                    
                    iss >> type_covered >> algorithm >> labels >> orig_ttl 
                        >> sig_exp >> sig_inc >> key_tag >> signer;
                    
                    // Type covered
                    uint16_t type = parseType(type_covered);
                    writeUint16(rdata, type);
                    
                    // Algorithm
                    writeUint8(rdata, std::stoi(algorithm));
                    
                    // Labels
                    writeUint8(rdata, std::stoi(labels));
                    
                    // Original TTL
                    writeUint32(rdata, std::stoul(orig_ttl));
                    
                    // Signature expiration (YYYYMMDDHHmmSS format)
                    writeUint32(rdata, parseTimestamp(sig_exp));
                    
                    // Signature inception
                    writeUint32(rdata, parseTimestamp(sig_inc));
                    
                    // Key tag
                    writeUint16(rdata, std::stoi(key_tag));
                    
                    // Signer's name
                    if (!signer.empty() && signer.back() != '.') signer += "." + origin;
                    auto signer_enc = commons::encodeDomainName(signer);
                    rdata.insert(rdata.end(), signer_enc.begin(), signer_enc.end());
                    
                    // Signature (base64, rest of line)
                    std::string sig_b64;
                    iss >> sig_b64;
                    
                    // Decode base64
                    auto signature = base64Decode(sig_b64);
                    rdata.insert(rdata.end(), signature.begin(), signature.end());
                    break;
                }

                case RR_TYPE_NSEC: {
                    // Format: next_domain_name type_bitmap
                    
                    std::string next_name;
                    iss >> next_name;
                    
                    if (!next_name.empty() && next_name.back() != '.') next_name += "." + origin;
                    auto next_enc = commons::encodeDomainName(next_name);
                    rdata.insert(rdata.end(), next_enc.begin(), next_enc.end());
                    
                    // Parse type bitmap
                    std::vector<uint16_t> types;
                    std::string type_str;
                    while (iss >> type_str) {
                        types.push_back(parseType(type_str));
                    }
                    
                    // Encode type bitmap
                    auto bitmap = encodeTypeBitmap(types);
                    rdata.insert(rdata.end(), bitmap.begin(), bitmap.end());
                    break;
                }

                case RR_TYPE_DNSKEY: {
                    // Format: flags protocol algorithm public_key
                    
                    std::string flags, protocol, algorithm, pubkey_b64;
                    iss >> flags >> protocol >> algorithm;
                    
                    writeUint16(rdata, std::stoi(flags));
                    writeUint8(rdata, std::stoi(protocol));
                    writeUint8(rdata, std::stoi(algorithm));
                    
                    // Public key (base64, rest of line)
                    std::string remaining;
                    std::getline(iss, remaining);
                    
                    // Remove whitespace
                    pubkey_b64 = remaining;
                    pubkey_b64.erase(std::remove_if(pubkey_b64.begin(), pubkey_b64.end(), 
                                    ::isspace), pubkey_b64.end());
                    
                    // Decode base64
                    auto pubkey = base64Decode(pubkey_b64);
                    rdata.insert(rdata.end(), pubkey.begin(), pubkey.end());
                    break;
                }

                case RR_TYPE_ZONEMD: {
                    // Format: serial scheme hash_algorithm digest
                    
                    std::string serial, scheme, hash_alg, digest_hex;
                    iss >> serial >> scheme >> hash_alg >> digest_hex;
                    
                    writeUint32(rdata, std::stoul(serial));
                    writeUint8(rdata, std::stoi(scheme));
                    writeUint8(rdata, std::stoi(hash_alg));
                    
                    // Parse hex digest (may span multiple tokens)
                    std::string remaining;
                    std::getline(iss, remaining);
                    digest_hex += remaining;
                    
                    // Remove whitespace and parentheses
                    digest_hex.erase(std::remove_if(digest_hex.begin(), digest_hex.end(), 
                                    [](char c) { return std::isspace(c) || c == '(' || c == ')'; }), 
                                    digest_hex.end());
                    
                    // Convert hex to bytes
                    for (size_t i = 0; i < digest_hex.length(); i += 2) {
                        std::string byte_str = digest_hex.substr(i, 2);
                        uint8_t byte = std::stoi(byte_str, nullptr, 16);
                        rdata.push_back(byte);
                    }
                    break;
                }
            }
            return rdata;
        }

        // Base64 decode (simplified)
        std::vector<uint8_t> base64Decode(const std::string& encoded) {
        static const std::string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
        
        std::vector<uint8_t> decoded;
        std::string cleaned;
        
        // Remove whitespace and padding
        for (char c : encoded) {
            if (!std::isspace(c) && c != '=') {
                cleaned += c;
            }
        }
        
        for (size_t i = 0; i < cleaned.length(); i += 4) {
            uint32_t val = 0;
            
            for (int j = 0; j < 4 && (i + j) < cleaned.length(); j++) {
                size_t pos = base64_chars.find(cleaned[i + j]);
                if (pos == std::string::npos) continue;
                val = (val << 6) | pos;
            }
            
            decoded.push_back((val >> 16) & 0xFF);
            if (i + 2 < cleaned.length()) decoded.push_back((val >> 8) & 0xFF);
            if (i + 3 < cleaned.length()) decoded.push_back(val & 0xFF);
        }
        
        return decoded;
    }
        // Encode type bitmap for NSEC
        std::vector<uint8_t> encodeTypeBitmap(const std::vector<uint16_t>& types) {
            if (types.empty()) return {};
            
            // Group types into windows (256 types per window)
            std::map<uint8_t, std::set<uint8_t>> windows;
            
            for (uint16_t type : types) {
                uint8_t window = type / 256;
                uint8_t bit = type % 256;
                windows[window].insert(bit);
            }
            
            std::vector<uint8_t> bitmap;
            for (const auto& pair : windows) {
                uint8_t window_num = pair.first;
                const auto& bits = pair.second;
                if (bits.empty()) continue;
                
                // Find highest bit
                uint8_t max_bit = *bits.rbegin();
                uint8_t bitmap_len = (max_bit / 8) + 1;
                
                bitmap.push_back(window_num);
                bitmap.push_back(bitmap_len);
                
                std::vector<uint8_t> window_bitmap(bitmap_len, 0);
                for (uint8_t bit : bits) {
                    uint8_t byte_pos = bit / 8;
                    uint8_t bit_pos = 7 - (bit % 8);
                    window_bitmap[byte_pos] |= (1 << bit_pos);
                }
                
                bitmap.insert(bitmap.end(), window_bitmap.begin(), window_bitmap.end());
            }
            
            return bitmap;
        }

        rr_type_t parseType(std::string& type_str) {
            std::string copy = commons::toUpper(type_str);     
            auto it = str_to_rr_type_t.find(copy);
            if (it != str_to_rr_type_t.end()) {
                return it->second;
            } else {
                throw std::runtime_error("Unknown RR type: " + copy);
            }
        }
    
        rr_class_t parseClass(std::string& class_str) {
            std::string copy = commons::toUpper(class_str);
            
            auto it = str_to_rr_class_t.find(copy);
            if (it != str_to_rr_class_t.end()) {
                return it->second;
            } else {
                throw std::runtime_error("Unknown RR class: " + copy);
            }
        }
    };

}

#endif // DNS_ZONE_PARSER_HPP