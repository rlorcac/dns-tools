#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include "dns/wire_format.hpp"

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

} // namespace dns