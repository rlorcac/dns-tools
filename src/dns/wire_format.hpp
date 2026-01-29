#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <stdexcept>

#ifndef DNS_WIRE_FORMAT_HPP // DNS_WIRE_FORMAT_HPP
#define DNS_WIRE_FORMAT_HPP

namespace dns {

    // Wire format helpers
    void writeUint8(std::vector<uint8_t>& buf, uint8_t val);

    void writeUint16(std::vector<uint8_t>& buf, uint16_t val);

    void writeUint32(std::vector<uint8_t>& buf, uint32_t val);

    uint16_t readUint16(const uint8_t* buf, size_t& offset);

    uint32_t readUint32(const uint8_t* buf, size_t& offset);

} // namespace dns

#endif // DNS_WIRE_FORMAT_HPP