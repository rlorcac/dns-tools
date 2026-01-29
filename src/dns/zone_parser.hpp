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

#include "string_commons.hpp"
#include "wire_format.hpp"
#include "rr.hpp"


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
                    rdata = commons::parseIPv4(ip);
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
                    rdata = commons::parseIPv6(ip);
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
                    writeUint32(rdata, commons::parseTimestamp(sig_exp));
                    
                    // Signature inception
                    writeUint32(rdata, commons::parseTimestamp(sig_inc));
                    
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
                    auto signature = commons::decodeBase64(sig_b64);
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
                    auto pubkey = commons::decodeBase64(pubkey_b64);
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