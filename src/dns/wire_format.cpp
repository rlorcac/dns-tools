#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include "wire_format.hpp"

namespace dns {

// Wire format helpers
void writeUint8(std::vector<uint8_t>& buf, uint8_t val) {
    buf.push_back(val);
}

void writeUint16(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back((val >> 8) & 0xFF);
    buf.push_back(val & 0xFF);
}

void writeUint32(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back((val >> 24) & 0xFF);
    buf.push_back((val >> 16) & 0xFF);
    buf.push_back((val >> 8) & 0xFF);
    buf.push_back(val & 0xFF);
}

uint16_t readUint16(const uint8_t* buf, size_t& offset) {
    uint16_t val = (buf[offset] << 8) | buf[offset+1];
    offset += 2;
    return val;
}

uint32_t readUint32(const uint8_t* buf, size_t& offset) {
    uint32_t val = (buf[offset] << 24) | (buf[offset+1] << 16) |
                   (buf[offset+2] << 8) | buf[offset+3];
    offset += 4;
    return val;
}

// DNS name encoding
std::vector<uint8_t> encodeName(const std::string& name) {
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

std::string toLower(std::string s) {
    for (auto& c : s) c = std::tolower(c);
    return s;
}

// Basic RR structure
struct RR {
    std::string name;
    uint16_t type;
    uint16_t rclass = 1; // IN
    uint32_t ttl;
    std::vector<uint8_t> rdata;
    
    std::vector<uint8_t> toWire() const {
        std::vector<uint8_t> wire;
        auto name_wire = encodeName(toLower(name));
        wire.insert(wire.end(), name_wire.begin(), name_wire.end());
        writeUint16(wire, type);
        writeUint16(wire, rclass);
        writeUint32(wire, ttl);
        writeUint16(wire, rdata.size());
        wire.insert(wire.end(), rdata.begin(), rdata.end());
        return wire;
    }
};

} // namespace dns