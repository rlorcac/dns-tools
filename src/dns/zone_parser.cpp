#include "wire_format.hpp"
#include "rr.hpp"
#include "zone_parser.hpp"
#include <fstream>
#include <unordered_map>
#include <ctime>
#include <algorithm>
#include <map>
#include <set>
#include <iostream>

namespace dns {
    std::vector<DNSResourceRecord> SimpleZoneParser::parse(const std::string& filename, const std::string& origin) {
        scanForDirectives(filename);    
        
        file.open(filename);
        if (!file) throw std::runtime_error("Cannot open file");
        
        std::vector<DNSResourceRecord> records;
        std::string line;
        
        while (std::getline(file, line)) {
            cleanupLine(line);
            
            if (line.empty()) continue;
            
            // Handle multi-line records with parentheses
            if (line.find('(') != std::string::npos) {
                line = readMultiLineRecord(line);
            }
            
            // Parse RR
            try {
                std::string stripped_line = line;
                stripped_line.erase(0, stripped_line.find_first_not_of(" \t"));
                stripped_line.erase(stripped_line.find_last_not_of(" \t\r\n") + 1);
                if (!stripped_line.empty()) {
                    DNSResourceRecord rr = parseRR(line);
                    records.push_back(rr);
                }
            } catch (const std::exception& e) {
                if (!line.empty() && line[0] == '$') continue; // Skip directives
                std::cerr << "Warning: Failed to parse line: " << line << "\n";
                std::cerr << "\tError: " << e.what() << "\n";
                continue; // Skip bad lines
            }
        }
        
        file.close();
        return records;
    }
    

} // namespace dns
